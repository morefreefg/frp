//go:build !frps

package kaboo

import (
	"context"
	"crypto/tls"
	"github.com/fatedier/frp/pkg/kaboo/trust"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTLSConnectorRejectsUntrustedServer(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("untrusted server must not receive application data")
	}))
	defer server.Close()
	connector := &tlsConnector{ctx: context.Background(), address: server.Listener.Addr().String(), status: func(string) {}, connections: make(map[*trackedTLSConn]struct{})}
	_, err := connector.Connect()
	require.Error(t, err)
	config := trust.ClientConfig()
	require.False(t, config.InsecureSkipVerify)
	require.Equal(t, uint16(tls.VersionTLS13), config.MinVersion)
	require.Equal(t, "kaboo-server", config.ServerName)
}
