package main

import (
	"errors"
	"fmt"
)

const proxyTLSProtocol = "hysteria-proxy"

type proxyClientConfig struct {
	SOCKS5Addr        string `json:"socks5_addr" desc:"SOCKS5 listen address"`
	SOCKS5Timeout     int    `json:"socks5_timeout" desc:"SOCKS5 connection timeout in seconds"`
	SOCKS5DisableUDP  bool   `json:"socks5_disable_udp" desc:"Disable SOCKS5 UDP support"`
	SOCKS5User        string `json:"socks5_user" desc:"SOCKS5 auth username"`
	SOCKS5Password    string `json:"socks5_password" desc:"SOCKS5 auth password"`
	HTTPAddr          string `json:"http_addr" desc:"HTTP listen address"`
	HTTPTimeout       int    `json:"http_timeout" desc:"HTTP connection timeout in seconds"`
	HTTPUser          string `json:"http_user" desc:"HTTP basic auth username"`
	HTTPPassword      string `json:"http_password" desc:"HTTP basic auth password"`
	HTTPSCert         string `json:"https_cert" desc:"HTTPS certificate file"`
	HTTPSKey          string `json:"https_key" desc:"HTTPS key file"`
	ACLFile           string `json:"acl" desc:"Access control list"`
	ServerAddr        string `json:"server" desc:"Server address"`
	Username          string `json:"username" desc:"Authentication username"`
	Password          string `json:"password" desc:"Authentication password"`
	Insecure          bool   `json:"insecure" desc:"Ignore TLS certificate errors"`
	CustomCAFile      string `json:"ca" desc:"Specify a trusted CA file"`
	UpMbps            int    `json:"up_mbps" desc:"Upload speed in Mbps"`
	DownMbps          int    `json:"down_mbps" desc:"Download speed in Mbps"`
	ReceiveWindowConn uint64 `json:"recv_window_conn" desc:"Max receive window size per connection"`
	ReceiveWindow     uint64 `json:"recv_window" desc:"Max receive window size"`
	Obfs              string `json:"obfs" desc:"Obfuscation key"`
}

func (c *proxyClientConfig) Check() error {
	if len(c.SOCKS5Addr) == 0 && len(c.HTTPAddr) == 0 {
		return errors.New("no SOCKS5 or HTTP listen address")
	}
	if c.SOCKS5Timeout != 0 && c.SOCKS5Timeout <= 4 {
		return errors.New("invalid SOCKS5 timeout")
	}
	if c.HTTPTimeout != 0 && c.HTTPTimeout <= 4 {
		return errors.New("invalid HTTP timeout")
	}
	if len(c.ServerAddr) == 0 {
		return errors.New("no server address")
	}
	if c.UpMbps <= 0 || c.DownMbps <= 0 {
		return errors.New("invalid speed")
	}
	if (c.ReceiveWindowConn != 0 && c.ReceiveWindowConn < 65536) ||
		(c.ReceiveWindow != 0 && c.ReceiveWindow < 65536) {
		return errors.New("invalid receive window size")
	}
	return nil
}

func (c *proxyClientConfig) String() string {
	return fmt.Sprintf("%+v", *c)
}

type proxyServerConfig struct {
	ListenAddr          string `json:"listen" desc:"Server listen address"`
	DisableUDP          bool   `json:"disable_udp" desc:"Disable UDP support"`
	ACLFile             string `json:"acl" desc:"Access control list"`
	CertFile            string `json:"cert" desc:"TLS certificate file"`
	KeyFile             string `json:"key" desc:"TLS key file"`
	AuthFile            string `json:"auth" desc:"Authentication file"`
	UpMbps              int    `json:"up_mbps" desc:"Max upload speed per client in Mbps"`
	DownMbps            int    `json:"down_mbps" desc:"Max download speed per client in Mbps"`
	ReceiveWindowConn   uint64 `json:"recv_window_conn" desc:"Max receive window size per connection"`
	ReceiveWindowClient uint64 `json:"recv_window_client" desc:"Max receive window size per client"`
	MaxConnClient       int    `json:"max_conn_client" desc:"Max simultaneous connections allowed per client"`
	Obfs                string `json:"obfs" desc:"Obfuscation key"`
}

func (c *proxyServerConfig) Check() error {
	if len(c.ListenAddr) == 0 {
		return errors.New("no listen address")
	}
	if len(c.CertFile) == 0 || len(c.KeyFile) == 0 {
		return errors.New("TLS cert or key not provided")
	}
	if c.UpMbps < 0 || c.DownMbps < 0 {
		return errors.New("invalid speed")
	}
	if (c.ReceiveWindowConn != 0 && c.ReceiveWindowConn < 65536) ||
		(c.ReceiveWindowClient != 0 && c.ReceiveWindowClient < 65536) {
		return errors.New("invalid receive window size")
	}
	if c.MaxConnClient < 0 {
		return errors.New("invalid max connections per client")
	}
	return nil
}

func (c *proxyServerConfig) String() string {
	return fmt.Sprintf("%+v", *c)
}
