package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fatedier/frp/pkg/config/securefile"
	"github.com/stretchr/testify/require"
)

func TestEncryptedClientAndServerConfiguration(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	require.NoError(t, securefile.GenerateKey(key))
	t.Setenv(securefile.KeyFileEnv, key)
	server := filepath.Join(dir, "server.yaml.enc")
	require.NoError(t, securefile.WriteFile(server, []byte("bindPort: 17000\nauth:\n  token: test-secret\n")))
	s, legacy, err := LoadServerConfig(server, true)
	require.NoError(t, err)
	require.False(t, legacy)
	require.Equal(t, 17000, s.BindPort)
	require.Equal(t, "test-secret", s.Auth.Token)
	client := filepath.Join(dir, "client.yaml.enc")
	require.NoError(t, securefile.WriteFile(client, []byte("serverAddr: 127.0.0.1\nserverPort: 17000\nauth:\n  token: test-secret\n")))
	c, err := LoadClientConfigResult(client, true)
	require.NoError(t, err)
	require.Equal(t, "test-secret", c.Common.Auth.Token)
	// A plaintext include must not bypass encrypted mode.
	include := filepath.Join(dir, "extra.yaml")
	require.NoError(t, os.WriteFile(include, []byte("proxies: []"), 0o600))
	_, _, err = LoadAdditionalClientConfigs([]string{include}, false, true)
	require.Error(t, err)
	require.NoError(t, securefile.WriteFile(server, []byte("bindPort: 17000\nwebServer:\n  port: 17500\n")))
	_, _, err = LoadServerConfig(server, true)
	require.ErrorContains(t, err, "dashboard username and password")
}
