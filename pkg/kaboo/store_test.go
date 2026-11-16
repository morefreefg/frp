package kaboo

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testClientState() *State {
	return &State{Version: 1, Role: Client, AuthToken: strings.Repeat("t", 43), SSPassword: strings.Repeat("s", 43), SSPort: 18388}
}
func testStore(t *testing.T) *Store {
	t.Helper()
	root := t.TempDir()
	return &Store{StateDir: filepath.Join(root, "state"), KeyDir: filepath.Join(root, "private"), Role: Client}
}

func TestEncryptedSettingsAndTwoFieldEndpoint(t *testing.T) {
	s := testStore(t)
	state := testClientState()
	endpoint := Endpoint{"127.0.0.1", 17000}
	require.NoError(t, s.Save(state, endpoint))
	b, err := os.ReadFile(filepath.Join(s.StateDir, "settings.enc"))
	require.NoError(t, err)
	require.NotContains(t, string(b), state.SSPassword)
	require.NotContains(t, string(b), state.AuthToken)
	got, ep, err := s.Load()
	require.NoError(t, err)
	require.Equal(t, state, got)
	require.Equal(t, endpoint, ep)
	file, err := os.ReadFile(filepath.Join(s.StateDir, "endpoint.json"))
	require.NoError(t, err)
	var keys map[string]any
	require.NoError(t, json.Unmarshal(file, &keys))
	require.Len(t, keys, 2)
	require.NoError(t, os.WriteFile(filepath.Join(s.StateDir, "endpoint.json"), []byte(`{"ip":"127.0.0.1","port":17001,"auth":{"token":"override"}}`), 0o600))
	_, _, err = s.Load()
	require.Error(t, err)
}

func TestMissingKeyAndTamperingPreserveSettings(t *testing.T) {
	s := testStore(t)
	require.NoError(t, s.Save(testClientState(), Endpoint{"127.0.0.1", 17000}))
	path := filepath.Join(s.StateDir, "settings.enc")
	initial, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.Remove(filepath.Join(s.KeyDir, "master.key")))
	_, _, err = s.Load()
	require.Error(t, err)
	still, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, initial, still)
}

func TestPairingPinsBuildTrustAndRejectsPrivateMaterial(t *testing.T) {
	state := testClientState()
	code, err := state.Pairing()
	require.NoError(t, err)
	paired, err := parsePairing(code)
	require.NoError(t, err)
	require.Equal(t, state, paired)
	_, err = parsePairing("kaboo://invalid")
	require.Error(t, err)
	state.PrivateKey = "must-not-be-in-client"
	require.Error(t, state.Validate(Client))
}
