package transport

import (
	"crypto/tls"
	"fmt"
	"github.com/lucas-clemente/quic-go"
	"github.com/tobyxdd/hysteria/pkg/conns/faketcp"
	"github.com/tobyxdd/hysteria/pkg/conns/udp"
	"github.com/tobyxdd/hysteria/pkg/conns/wechat"
	"github.com/tobyxdd/hysteria/pkg/obfs"
	"net"
	"time"
)

type ServerTransport struct {
	Dialer        *net.Dialer
	SOCKS5Client  *SOCKS5Client
	PrefEnabled   bool
	PrefIPv6      bool
	PrefExclusive bool
}

type PUDPConn interface {
	ReadFromUDP([]byte) (int, *net.UDPAddr, error)
	WriteToUDP([]byte, *net.UDPAddr) (int, error)
	Close() error
}

var DefaultServerTransport = &ServerTransport{
	Dialer: &net.Dialer{
		Timeout: 8 * time.Second,
	},
	PrefEnabled: false,
}

func (st *ServerTransport) quicPacketConn(proto string, laddr string, obfs obfs.Obfuscator) (net.PacketConn, error) {
	if len(proto) == 0 || proto == "udp" {
		laddrU, err := net.ResolveUDPAddr("udp", laddr)
		if err != nil {
			return nil, err
		}
		conn, err := net.ListenUDP("udp", laddrU)
		if err != nil {
			return nil, err
		}
		if obfs != nil {
			oc := udp.NewObfsUDPConn(conn, obfs)
			return oc, nil
		} else {
			return conn, nil
		}
	} else if proto == "wechat-video" {
		laddrU, err := net.ResolveUDPAddr("udp", laddr)
		if err != nil {
			return nil, err
		}
		conn, err := net.ListenUDP("udp", laddrU)
		if err != nil {
			return nil, err
		}
		if obfs != nil {
			oc := wechat.NewObfsWeChatUDPConn(conn, obfs)
			return oc, nil
		} else {
			return conn, nil
		}
	} else if proto == "faketcp" {
		conn, err := faketcp.Listen("tcp", laddr)
		if err != nil {
			return nil, err
		}
		if obfs != nil {
			oc := faketcp.NewObfsFakeTCPConn(conn, obfs)
			return oc, nil
		} else {
			return conn, nil
		}
	} else {
		return nil, fmt.Errorf("unsupported protocol: %s", proto)
	}
}

func (ct *ServerTransport) QUICListen(proto string, listen string, tlsConfig *tls.Config, quicConfig *quic.Config, obfs obfs.Obfuscator) (quic.Listener, error) {
	pktConn, err := ct.quicPacketConn(proto, listen, obfs)
	if err != nil {
		return nil, err
	}
	l, err := quic.Listen(pktConn, tlsConfig, quicConfig)
	if err != nil {
		_ = pktConn.Close()
		return nil, err
	}
	return l, nil
}

func (ct *ServerTransport) ResolveIPAddr(address string) (*net.IPAddr, error) {
	if ct.PrefEnabled {
		return resolveIPAddrWithPreference(address, ct.PrefIPv6, ct.PrefExclusive)
	} else {
		return net.ResolveIPAddr("ip", address)
	}
}

func (ct *ServerTransport) DialTCP(raddr *net.TCPAddr) (*net.TCPConn, error) {
	if ct.SOCKS5Client != nil {
		return ct.SOCKS5Client.DialTCP(raddr)
	} else {
		conn, err := ct.Dialer.Dial("tcp", raddr.String())
		if err != nil {
			return nil, err
		}
		return conn.(*net.TCPConn), nil
	}
}

func (ct *ServerTransport) ListenUDP() (PUDPConn, error) {
	if ct.SOCKS5Client != nil {
		return ct.SOCKS5Client.ListenUDP()
	} else {
		return net.ListenUDP("udp", nil)
	}
}
