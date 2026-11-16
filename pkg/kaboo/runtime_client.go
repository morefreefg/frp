// Copyright 2026 The frp Authors
// SPDX-License-Identifier: Apache-2.0
//go:build !frps

package kaboo

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/fatedier/frp/client"
	"github.com/fatedier/frp/client/proxy"
	"github.com/fatedier/frp/pkg/config/source"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/kaboo/trust"
	"github.com/fatedier/frp/pkg/policy/security"
)

func RunClient(ctx context.Context, state *State, endpoint Endpoint, status func(string)) error {
	ss, err := startSS(ctx, state.SSPassword)
	if err != nil {
		return err
	}
	defer ss.Close()
	cfg := &v1.ClientCommonConfig{ServerAddr: endpoint.IP, ServerPort: endpoint.Port, ClientID: "kaboo-cli", UDPPacketSize: 65507}
	cfg.Auth.Method = "token"
	cfg.Auth.Token = state.AuthToken
	cfg.Auth.AdditionalScopes = []v1.AuthScope{"HeartBeats", "NewWorkConns"}
	cfg.Transport.TCPMux = new(false)
	cfg.Transport.WireProtocol = "v2"
	if err := cfg.Complete(); err != nil {
		return err
	}
	baseTCP := v1.ProxyBaseConfig{Name: "kaboo-ss-tcp", Type: "tcp", ProxyBackend: v1.ProxyBackend{LocalIP: "127.0.0.1", LocalPort: ss.Port}}
	baseUDP := v1.ProxyBaseConfig{Name: "kaboo-ss-udp", Type: "udp", ProxyBackend: v1.ProxyBackend{LocalIP: "127.0.0.1", LocalPort: ss.Port}}
	proxies := []v1.ProxyConfigurer{&v1.TCPProxyConfig{ProxyBaseConfig: baseTCP, RemotePort: state.SSPort}, &v1.UDPProxyConfig{ProxyBaseConfig: baseUDP, RemotePort: state.SSPort}}
	src := source.NewConfigSource()
	if err := src.ReplaceAll(proxies, nil); err != nil {
		return err
	}
	svc, err := client.NewService(client.ServiceOptions{Common: cfg, ConfigSourceAggregator: source.NewAggregator(src), UnsafeFeatures: security.NewUnsafeFeatures(nil),
		ConnectorCreator: func(c context.Context, cfg *v1.ClientCommonConfig) client.Connector {
			return &tlsConnector{ctx: c, address: net.JoinHostPort(cfg.ServerAddr, strconv.Itoa(cfg.ServerPort)), connections: make(map[*trackedTLSConn]struct{}), status: status}
		}})
	if err != nil {
		return err
	}
	defer svc.Close()
	status("正在连接并验证服务端证书")
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		wasReady := false
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				tcp, tcpOK := svc.StatusExporter().GetProxyStatus("kaboo-ss-tcp")
				udp, udpOK := svc.StatusExporter().GetProxyStatus("kaboo-ss-udp")
				ready := tcpOK && udpOK && tcp.Phase == proxy.ProxyPhaseRunning && udp.Phase == proxy.ProxyPhaseRunning
				if ready {
					status("TLS 1.3 已连接；SS 的 TCP、UDP 转发就绪")
				} else if wasReady {
					status("隧道已断开；正在重连")
				}
				wasReady = ready
			}
		}
	}()
	return svc.Run(ctx)
}

// Each connection, including control and UDP work connections, is authenticated
// TLS 1.3. There is no plaintext or unverified fallback.
type tlsConnector struct {
	ctx         context.Context
	address     string
	status      func(string)
	mu          sync.Mutex
	closed      bool
	connections map[*trackedTLSConn]struct{}
}

func (c *tlsConnector) Open() error { return nil }
func (c *tlsConnector) Connect() (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	raw, err := dialer.DialContext(c.ctx, "tcp", c.address)
	if err != nil {
		c.status("连接暂不可用；正在重试")
		return nil, err
	}
	secured := tls.Client(raw, trust.ClientConfig())
	ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()
	if err := secured.HandshakeContext(ctx); err != nil {
		raw.Close()
		c.status("证书验证或 TLS 握手失败；正在重试")
		return nil, err
	}
	if secured.ConnectionState().NegotiatedProtocol != "kaboo/1" {
		raw.Close()
		return nil, errors.New("unexpected TLS application protocol")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		secured.Close()
		return nil, net.ErrClosed
	}
	conn := &trackedTLSConn{Conn: secured, owner: c}
	c.connections[conn] = struct{}{}
	c.status("TLS 1.3 证书已验证；正在建立转发会话")
	return conn, nil
}

func (c *tlsConnector) Close() error {
	c.mu.Lock()
	c.closed = true
	active := make([]*trackedTLSConn, 0, len(c.connections))
	for conn := range c.connections {
		active = append(active, conn)
	}
	c.mu.Unlock()
	for _, conn := range active {
		conn.Close()
	}
	return nil
}

type trackedTLSConn struct {
	net.Conn
	owner *tlsConnector
	once  sync.Once
	err   error
}

func (c *trackedTLSConn) Close() error {
	c.once.Do(func() { c.owner.mu.Lock(); delete(c.owner.connections, c); c.owner.mu.Unlock(); c.err = c.Conn.Close() })
	return c.err
}
