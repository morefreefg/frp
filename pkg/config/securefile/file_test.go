package securefile

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func setupKey(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key")
	require.NoError(t, GenerateKey(path))
	t.Setenv(KeyFileEnv, path)
	return path
}

func TestAuthenticatedEncryption(t *testing.T) {
	setupKey(t)
	plain := []byte("auth:\n  token: a-secret-that-must-not-be-on-disk\n")
	first, err := Encrypt(plain)
	require.NoError(t, err)
	second, err := Encrypt(plain)
	require.NoError(t, err)
	require.NotEqual(t, first, second, "each write needs a new nonce")
	require.False(t, bytes.Contains(first, []byte("a-secret")))
	decoded, err := Decrypt(first)
	require.NoError(t, err)
	require.Equal(t, plain, decoded)
	first[len(first)-1] ^= 1
	_, err = Decrypt(first)
	require.Error(t, err)
	_, err = Decrypt([]byte(magic))
	require.Error(t, err)
}

func TestWrongKeyAndPlaintextRefusal(t *testing.T) {
	setupKey(t)
	enc, err := Encrypt([]byte("bindPort: 7000"))
	require.NoError(t, err)
	setupKey(t)
	_, err = Decrypt(enc)
	require.Error(t, err)
	path := filepath.Join(t.TempDir(), "plain.yaml")
	require.NoError(t, os.WriteFile(path, []byte("bindPort: 7000"), 0o600))
	_, err = ReadFile(path)
	require.ErrorContains(t, err, "plaintext")
}

func TestAtomicSaveNeverDowngrades(t *testing.T) {
	setupKey(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, WriteFile(path, []byte("first secret")))
	onDisk, err := os.ReadFile(path)
	require.NoError(t, err)
	require.True(t, IsEncrypted(onDisk))
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	t.Setenv(KeyFileEnv, "")
	require.Error(t, WriteFile(path, []byte("second secret")))
	current, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, onDisk, current)
	_, err = ReadFile(path)
	require.Error(t, err)
}

func TestKeyPermissionsAndOverwrite(t *testing.T) {
	path := setupKey(t)
	require.Error(t, GenerateKey(path))
	require.NoError(t, os.Chmod(path, 0o644))
	_, err := Encrypt([]byte("secret"))
	require.Error(t, err)
}

func TestPlaintextCompatibilityAndEncryptedSuffix(t *testing.T) {
	t.Setenv(KeyFileEnv, "")
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, WriteFile(path, []byte("plain")))
	b, err := ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "plain", string(b))
	require.Error(t, WriteFile(path+".enc", []byte("secret")))
	require.NoError(t, os.WriteFile(path+".enc", b, 0o600))
	_, err = ReadFile(path + ".enc")
	require.ErrorContains(t, err, "plaintext")
}
