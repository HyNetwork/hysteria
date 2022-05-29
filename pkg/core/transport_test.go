package core

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"testing"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/sirupsen/logrus"
	hyCongestion "github.com/tobyxdd/hysteria/pkg/congestion"
	"github.com/tobyxdd/hysteria/pkg/obfs"
	"github.com/tobyxdd/hysteria/pkg/transport"
)

// Configs for testing
const (
	server_addr      = "localhost:2345"
	protocol         = ""
	certFile         = "../../hysteria.server.crt"
	keyFile          = "../../hysteria.server.key"
	obfs_str         = "f561508f56ed"
	auth_str         = "da5438aaa690a5748eb59de8f7bedcb0"
	client_up_mbps   = 20
	client_down_mbps = 1000
	server_name      = "www.0e6e852f62bbeb99.com"
	test_data        = "Here we go!"
	customCA         = "../../hysteria.ca.crt"
)

// Default config copied from cmd/config.go
const (
	mbpsToBps   = 125000
	minSpeedBPS = 16384

	DefaultStreamReceiveWindow     = 15728640 // 15 MB/s
	DefaultConnectionReceiveWindow = 67108864 // 64 MB/s
	DefaultMaxIncomingStreams      = 1024

	DefaultALPN = "hysteria"
)

func TestE2E(t *testing.T) {
	// Server and Client share the same obfuscator
	obfuscator := obfs.NewXPlusObfuscator([]byte(obfs_str))

	go runServer(obfuscator)

	time.Sleep(time.Second * 5)
	err := runClient(obfuscator)
	if err != nil {
		t.Fail()
	}
}

// Simulate a server
func runServer(obfuscator *obfs.XPlusObfuscator) error {
	// Load TLS server config
	cer, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		fmt.Println("Cannot read server cert or key files")
		return err
	}

	var serverTlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cer},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{DefaultALPN},
	}

	// QUIC config
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     DefaultStreamReceiveWindow,
		MaxStreamReceiveWindow:         DefaultStreamReceiveWindow,
		InitialConnectionReceiveWindow: DefaultConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     DefaultConnectionReceiveWindow,
		MaxIncomingStreams:             DefaultMaxIncomingStreams, // Client doesn't need this
		KeepAlive:                      true,
		DisablePathMTUDiscovery:        true, // @TODO: not sure what does this mean yet
		EnableDatagrams:                true,
	}

	// Auth
	var authFunc ConnectFunc
	authFunc, err = passwordAuthFunc(auth_str)
	connectFunc := func(addr net.Addr, auth []byte, sSend uint64, sRecv uint64) (bool, string) {
		ok, msg := authFunc(addr, auth, sSend, sRecv)
		if !ok {
			logrus.WithFields(logrus.Fields{
				"src": addr,
				"msg": msg,
			}).Info("Authentication failed, client rejected")
		} else {
			logrus.WithFields(logrus.Fields{
				"src": addr,
			}).Info("Client connected")
		}
		return ok, msg
	}

	server := &HysteriaTransport{
		addr:              server_addr,
		protocol:          protocol,
		tlsConfig:         serverTlsConfig,
		quicConfig:        quicConfig,
		transport:         transport.DefaultServerTransport,
		sendBPS:           0,
		recvBPS:           0,
		congestionFactory: congestionFactory,
		disableUDP:        false,
		obfuscator:        obfuscator,
		connectFunc:       connectFunc,
		disconnectFunc:    disconnectFunc,
	}

	l, err := server.Listen()

	if err != nil {
		fmt.Println("Failed to initialize server")
	}

	fmt.Println("Server up and running")

	for {
		serverConn, err := l.Accept()
		serverBuffer := make([]byte, len(test_data))
		_, err = serverConn.Read(serverBuffer)

		if err != nil {
			return err
		}

		s := string(serverBuffer)
		if s == test_data {
			serverConn.Close()
			return nil
		}
	}
}

// Simulate a client
func runClient(obfuscator *obfs.XPlusObfuscator) error {
	// Load TLS client config
	var clientTlsConfig = &tls.Config{
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{DefaultALPN},
		ServerName:         server_name,
	}
	bs, err := ioutil.ReadFile(customCA)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
			"file":  customCA,
		}).Fatal("Failed to load CA")
	}
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM(bs) {
		logrus.WithFields(logrus.Fields{
			"file": customCA,
		}).Fatal("Failed to parse CA")
	}
	clientTlsConfig.RootCAs = cp

	// QUIC config
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     DefaultStreamReceiveWindow,
		MaxStreamReceiveWindow:         DefaultStreamReceiveWindow,
		InitialConnectionReceiveWindow: DefaultConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     DefaultConnectionReceiveWindow,
		KeepAlive:                      true,
		DisablePathMTUDiscovery:        true, // @TODO: not sure what does this mean yet
		EnableDatagrams:                true,
	}

	client, err := NewClient(server_addr, protocol, []byte(auth_str), clientTlsConfig, quicConfig,
		transport.DefaultClientTransport, client_up_mbps, client_down_mbps,
		congestionFactory, obfuscator)

	if err != nil {
		fmt.Println("Failed to initialize client")
		return err
	}

	fmt.Println("Client up and running")

	clientConn, err := client.Dial()

	if err != nil {
		fmt.Println("Failed to connect to the server")
		return err
	}

	//write data from clientConn for server to read
	_, clientWriteErr := clientConn.Write([]byte(test_data))
	return clientWriteErr
}

// Below are default functions copied from cmd/server.go or cmd/client.go

// Use Hysteria custom congestion
func congestionFactory(refBPS uint64) congestion.CongestionControl {
	return hyCongestion.NewBrutalSender(congestion.ByteCount(refBPS))
}

func passwordAuthFunc(pwd string) (ConnectFunc, error) {
	var pwds []string
	pwds = []string{pwd}
	return func(addr net.Addr, auth []byte, sSend uint64, sRecv uint64) (bool, string) {
		for _, pwd := range pwds {
			if string(auth) == pwd {
				return true, "Welcome"
			}
		}
		return false, "Wrong password"
	}, nil
}

func disconnectFunc(addr net.Addr, auth []byte, err error) {
	logrus.WithFields(logrus.Fields{
		"src":   addr,
		"error": err,
	}).Info("Client disconnected")
}
