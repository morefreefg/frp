package client

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fatedier/frp/pkg/config/securefile"
	"github.com/fatedier/frp/pkg/policy/security"
	"github.com/stretchr/testify/require"
)

func TestConfigManagerKeepsEncryptedFile(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	require.NoError(t, securefile.GenerateKey(key))
	t.Setenv(securefile.KeyFileEnv, key)
	path := filepath.Join(dir, "client.yaml.enc")
	require.NoError(t, securefile.WriteFile(path, []byte("serverAddr: 127.0.0.1\nserverPort: 7000\n")))
	m := &serviceConfigManager{svr: &Service{configFilePath: path, unsafeFeatures: security.NewUnsafeFeatures(nil)}}
	next := "serverAddr: 127.0.0.1\nserverPort: 7001\nauth:\n  token: private-token\n"
	require.NoError(t, m.WriteConfigFile([]byte(next)))
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	require.True(t, securefile.IsEncrypted(b))
	require.NotContains(t, string(b), "private-token")
	got, err := m.ReadConfigFile()
	require.NoError(t, err)
	require.Equal(t, next, got)
	require.Error(t, m.WriteConfigFile([]byte("serverPort: not-a-number")))
	still, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, b, still)
}
