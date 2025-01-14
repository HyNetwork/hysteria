package outbounds

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/apernet/quic-go"
	"github.com/miekg/dns"
)

// DoqResolver Client stores a DoQ client
type DoqResolver struct {
	Resolver doqClient
	Next     PluggableOutbound
}

type doqClient struct {
	ctx  context.Context
	conn quic.Connection
}

func NewDOQResolver(server, sni string, tlsInsecureSkipVerify bool, next PluggableOutbound) (PluggableOutbound, error) {
	d, err := newDoqClient(server, sni, tlsInsecureSkipVerify)
	if err != nil {
		return nil, err
	}

	return &DoqResolver{
		Resolver: *d,
		Next:     next,
	}, nil
}

func newDoqClient(server, sni string, tlsInsecureSkipVerify bool) (*doqClient, error) {
	var d doqClient
	var err error
	d.ctx = context.Background()
	serverAddr := strings.SplitN(server, ":", 2)
	if len(serverAddr) != 2 {
		// DOQ: If the port is not specified, use the default port 853
		server = server + ":853"
	}
	if sni == "" {
		// DOQ: If the SNI is not specified, use the server address host
		sni = serverAddr[0]
	}
	d.conn, err = quic.DialAddrEarly(d.ctx, server, &tls.Config{
		ServerName:             sni,
		InsecureSkipVerify:     tlsInsecureSkipVerify,
		NextProtos:             []string{"doq"},
		SessionTicketsDisabled: false,
	}, &quic.Config{
		KeepAlivePeriod: 20 * time.Second,
		TokenStore:      quic.NewLRUTokenStore(1, 10),
	})
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func (r *DoqResolver) resolve(reqAddr *AddrEx) {
	if tryParseIP(reqAddr) {
		// The host is already an IP address, we don't need to resolve it.
		return
	}
	type lookupResult struct {
		ip  net.IP
		err error
	}
	ch4, ch6 := make(chan lookupResult, 1), make(chan lookupResult, 1)
	go func() {
		recs, err := r.Resolver.LookupA(reqAddr.Host)
		var ip net.IP
		if err == nil && len(recs) > 0 {
			ip = recs[0].A
		}
		ch4 <- lookupResult{ip, err}
	}()
	go func() {
		recs, err := r.Resolver.LookupAAAA(reqAddr.Host)
		var ip net.IP
		if err == nil && len(recs) > 0 {
			ip = recs[0].AAAA
		}
		ch6 <- lookupResult{ip, err}
	}()
	result4, result6 := <-ch4, <-ch6
	reqAddr.ResolveInfo = &ResolveInfo{
		IPv4: result4.ip,
		IPv6: result6.ip,
	}
	if result4.err != nil {
		reqAddr.ResolveInfo.Err = result4.err
	} else if result6.err != nil {
		reqAddr.ResolveInfo.Err = result6.err
	}
}

func (r *DoqResolver) TCP(reqAddr *AddrEx) (net.Conn, error) {
	r.resolve(reqAddr)
	return r.Next.TCP(reqAddr)
}

func (r *DoqResolver) UDP(reqAddr *AddrEx) (UDPConn, error) {
	r.resolve(reqAddr)
	return r.Next.UDP(reqAddr)
}

// Close closes a Client QUIC connection
func (c *doqClient) Close() error {
	return c.conn.CloseWithError(0, "")
}

func (c *doqClient) LookupA(name string) ([]dns.A, error) {
	var msg dns.Msg
	msg.SetQuestion(fmt.Sprintf("%s.", name), dns.TypeA)
	resp, err := c.Lookup(msg)
	if err != nil {
		return nil, err
	}
	var ret []dns.A
	for _, a := range resp.Answer {
		if ans, ok := a.(*dns.A); ok {
			ret = append(ret, *ans)
		}
	}
	return ret, nil
}

func (c *doqClient) LookupAAAA(name string) ([]dns.AAAA, error) {
	var msg dns.Msg
	msg.SetQuestion(fmt.Sprintf("%s.", name), dns.TypeAAAA)
	resp, err := c.Lookup(msg)
	if err != nil {
		return nil, err
	}
	var ret []dns.AAAA
	for _, a := range resp.Answer {
		if ans, ok := a.(*dns.AAAA); ok {
			ret = append(ret, *ans)
		}
	}
	return ret, nil
}

// Lookup sends a DNS query to the server and returns the response
// Code From: https://github.com/natesales/doqd/blob/main/pkg/client/main.go
func (c *doqClient) Lookup(message dns.Msg) (dns.Msg, error) {
	// Open a new QUIC stream
	stream, err := c.conn.OpenStreamSync(c.ctx)
	if err != nil {
		return dns.Msg{}, errors.New("quic stream open: " + err.Error())
	}

	// Pack the DNS message for transmission
	packed, err := message.Pack()
	if err != nil {
		_ = stream.Close()
		return dns.Msg{}, errors.New("dns message pack: " + err.Error())
	}

	_, err = stream.Write(packed)
	if err != nil {
		_ = stream.Close()
		return dns.Msg{}, errors.New("quic stream write: " + err.Error())
	}
	// Close the stream after writing the message
	_ = stream.Close()

	// Read the response from the QUIC stream
	buffer, err := io.ReadAll(stream)
	if err != nil {
		return dns.Msg{}, errors.New("quic stream read: " + err.Error())
	}

	// Unpack the DNS message
	var msg dns.Msg
	err = msg.Unpack(buffer)
	if err != nil {
		return dns.Msg{}, errors.New("dns message unpack: " + err.Error())
	}

	return msg, nil // nil error
}
