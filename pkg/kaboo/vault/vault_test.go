package vault

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAuthenticatedVaultAndPurposeSeparation(t *testing.T) {
	key := RandomKey()
	plain := []byte("private-key-and-password")
	first, err := Seal(plain, key, "settings:server")
	require.NoError(t, err)
	second, err := Seal(plain, key, "settings:server")
	require.NoError(t, err)
	require.NotEqual(t, first, second)
	require.NotContains(t, string(first), string(plain))
	got, err := Open(first, key, "settings:server")
	require.NoError(t, err)
	require.Equal(t, plain, got)
	_, err = Open(first, key, "deployment-private-key")
	require.Error(t, err)
	_, err = Open(first, RandomKey(), "settings:server")
	require.Error(t, err)
	var e envelope
	require.NoError(t, json.Unmarshal(first, &e))
	e.Data = "AAAA"
	damaged, err := json.Marshal(e)
	require.NoError(t, err)
	_, err = Open(damaged, key, "settings:server")
	require.Error(t, err)
}
