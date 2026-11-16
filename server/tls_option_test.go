package server

import (
	"crypto/tls"
	"net"
	"testing"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/transport"
	"github.com/stretchr/testify/require"
)

func TestInMemoryTLSIdentityOption(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close())
	cfg := &v1.ServerConfig{BindAddr: "127.0.0.1", BindPort: port}
	require.NoError(t, cfg.Complete())
	identity, err := transport.NewServerTLSConfig("", "", "")
	require.NoError(t, err)
	identity.MinVersion = tls.VersionTLS13
	svc, err := NewService(cfg, WithTLSConfig(identity))
	require.NoError(t, err)
	defer svc.Close()
	require.Equal(t, uint16(tls.VersionTLS13), svc.tlsConfig.MinVersion)
	require.Equal(t, identity.Certificates[0].Certificate, svc.tlsConfig.Certificates[0].Certificate)
	require.NotSame(t, identity, svc.tlsConfig)
}
