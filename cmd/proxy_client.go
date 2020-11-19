package main

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/sirupsen/logrus"
	"github.com/tobyxdd/hysteria/pkg/acl"
	hyCongestion "github.com/tobyxdd/hysteria/pkg/congestion"
	"github.com/tobyxdd/hysteria/pkg/core"
	hyHTTP "github.com/tobyxdd/hysteria/pkg/http"
	"github.com/tobyxdd/hysteria/pkg/obfs"
	"github.com/tobyxdd/hysteria/pkg/socks5"
)

func proxyClient(args []string) {
	var config proxyClientConfig
	err := loadConfig(&config, args)
	if err != nil {
		logrus.WithField("error", err).Fatal("Unable to load configuration")
	}
	if err := config.Check(); err != nil {
		logrus.WithField("error", err).Fatal("Configuration error")
	}
	logrus.WithField("config", config.String()).Info("Configuration loaded")

	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.Insecure,
		NextProtos:         []string{proxyTLSProtocol},
		MinVersion:         tls.VersionTLS13,
	}
	// Load CA
	if len(config.CustomCAFile) > 0 {
		bs, err := ioutil.ReadFile(config.CustomCAFile)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
				"file":  config.CustomCAFile,
			}).Fatal("Unable to load CA file")
		}
		cp := x509.NewCertPool()
		if !cp.AppendCertsFromPEM(bs) {
			logrus.WithFields(logrus.Fields{
				"file": config.CustomCAFile,
			}).Fatal("Unable to parse CA file")
		}
		tlsConfig.RootCAs = cp
	}

	quicConfig := &quic.Config{
		MaxReceiveStreamFlowControlWindow:     config.ReceiveWindowConn,
		MaxReceiveConnectionFlowControlWindow: config.ReceiveWindow,
		KeepAlive:                             true,
	}
	if quicConfig.MaxReceiveStreamFlowControlWindow == 0 {
		quicConfig.MaxReceiveStreamFlowControlWindow = DefaultMaxReceiveStreamFlowControlWindow
	}
	if quicConfig.MaxReceiveConnectionFlowControlWindow == 0 {
		quicConfig.MaxReceiveConnectionFlowControlWindow = DefaultMaxReceiveConnectionFlowControlWindow
	}

	var obfuscator core.Obfuscator
	if len(config.Obfs) > 0 {
		obfuscator = obfs.XORObfuscator(config.Obfs)
	}

	var aclEngine *acl.Engine
	if len(config.ACLFile) > 0 {
		aclEngine, err = acl.LoadFromFile(config.ACLFile)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
				"file":  config.ACLFile,
			}).Fatal("Unable to parse ACL")
		}
	}

	client, err := core.NewClient(config.ServerAddr, config.Username, config.Password, tlsConfig, quicConfig,
		uint64(config.UpMbps)*mbpsToBps, uint64(config.DownMbps)*mbpsToBps,
		func(refBPS uint64) congestion.ExternalSendAlgorithm {
			return hyCongestion.NewBrutalSender(congestion.ByteCount(refBPS))
		}, obfuscator)
	if err != nil {
		logrus.WithField("error", err).Fatal("Client initialization failed")
	}
	defer client.Close()
	logrus.WithField("addr", config.ServerAddr).Info("Connected")

	errChan := make(chan error)

	if len(config.SOCKS5Addr) > 0 {
		go func() {
			var authFunc func(user, password string) bool
			if config.SOCKS5User != "" && config.SOCKS5Password != "" {
				authFunc = func(user, password string) bool {
					return config.SOCKS5User == user && config.SOCKS5Password == password
				}
			}
			socks5server, err := socks5.NewServer(client, config.SOCKS5Addr, authFunc, config.SOCKS5Timeout, aclEngine,
				config.SOCKS5DisableUDP,
				func(addr net.Addr, reqAddr string, action acl.Action, arg string) {
					logrus.WithFields(logrus.Fields{
						"action": actionToString(action, arg),
						"src":    addr.String(),
						"dst":    reqAddr,
					}).Debug("New SOCKS5 TCP request")
				},
				func(addr net.Addr, reqAddr string, err error) {
					logrus.WithFields(logrus.Fields{
						"error": err,
						"src":   addr.String(),
						"dst":   reqAddr,
					}).Debug("SOCKS5 TCP request closed")
				},
				func(addr net.Addr) {
					logrus.WithFields(logrus.Fields{
						"src": addr.String(),
					}).Debug("New SOCKS5 UDP associate request")
				},
				func(addr net.Addr, err error) {
					logrus.WithFields(logrus.Fields{
						"error": err,
						"src":   addr.String(),
					}).Debug("SOCKS5 UDP associate request closed")
				},
				func(addr net.Addr, reqAddr string, action acl.Action, arg string) {
					logrus.WithFields(logrus.Fields{
						"action": actionToString(action, arg),
						"src":    addr.String(),
						"dst":    reqAddr,
					}).Debug("New SOCKS5 UDP tunnel")
				},
				func(addr net.Addr, reqAddr string, err error) {
					logrus.WithFields(logrus.Fields{
						"error": err,
						"src":   addr.String(),
						"dst":   reqAddr,
					}).Debug("SOCKS5 UDP tunnel closed")
				})
			if err != nil {
				logrus.WithField("error", err).Fatal("SOCKS5 server initialization failed")
			}
			logrus.WithField("addr", config.SOCKS5Addr).Info("SOCKS5 server up and running")
			errChan <- socks5server.ListenAndServe()
		}()
	}

	if len(config.HTTPAddr) > 0 {
		go func() {
			var authFunc func(user, password string) bool
			if config.HTTPUser != "" && config.HTTPPassword != "" {
				authFunc = func(user, password string) bool {
					return config.HTTPUser == user && config.HTTPPassword == password
				}
			}
			proxy, err := hyHTTP.NewProxyHTTPServer(client, time.Duration(config.HTTPTimeout)*time.Second, aclEngine,
				func(reqAddr string, action acl.Action, arg string) {
					logrus.WithFields(logrus.Fields{
						"action": actionToString(action, arg),
						"dst":    reqAddr,
					}).Debug("New HTTP request")
				},
				authFunc)
			if err != nil {
				logrus.WithField("error", err).Fatal("HTTP server initialization failed")
			}
			if config.HTTPSCert != "" && config.HTTPSKey != "" {
				logrus.WithField("addr", config.HTTPAddr).Info("HTTPS server up and running")
				errChan <- http.ListenAndServeTLS(config.HTTPAddr, config.HTTPSCert, config.HTTPSKey, proxy)
			} else {
				logrus.WithField("addr", config.HTTPAddr).Info("HTTP server up and running")
				errChan <- http.ListenAndServe(config.HTTPAddr, proxy)
			}
		}()
	}

	err = <-errChan
	logrus.WithField("error", err).Fatal("Client shutdown")
}

func actionToString(action acl.Action, arg string) string {
	switch action {
	case acl.ActionDirect:
		return "Direct"
	case acl.ActionProxy:
		return "Proxy"
	case acl.ActionBlock:
		return "Block"
	case acl.ActionHijack:
		return "Hijack to " + arg
	default:
		return "Unknown"
	}
}
