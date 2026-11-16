package source

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fatedier/frp/pkg/config/securefile"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/stretchr/testify/require"
)

func TestStoreEncryptsAndReloadsRules(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	require.NoError(t, securefile.GenerateKey(key))
	t.Setenv(securefile.KeyFileEnv, key)
	path := filepath.Join(dir, "store.json.enc")
	s, err := NewStoreSource(StoreSourceConfig{Path: path})
	require.NoError(t, err)
	p := &v1.TCPProxyConfig{ProxyBaseConfig: v1.ProxyBaseConfig{Name: "private-rule", Type: "tcp"}, RemotePort: 18080}
	require.NoError(t, s.AddProxy(p))
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	require.True(t, securefile.IsEncrypted(b))
	require.NotContains(t, string(b), "private-rule")
	reloaded, err := NewStoreSource(StoreSourceConfig{Path: path})
	require.NoError(t, err)
	require.NotNil(t, reloaded.GetProxy("private-rule"))
	// A failed write must retain both the encrypted file and in-memory rules.
	t.Setenv(securefile.KeyFileEnv, "")
	require.Error(t, s.RemoveProxy("private-rule"))
	require.NotNil(t, s.GetProxy("private-rule"))
	still, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, b, still)
}
