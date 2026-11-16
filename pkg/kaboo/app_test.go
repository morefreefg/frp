package kaboo

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestWebInitializationAuthenticationAndEncryptedPersistence(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := testStore(t)
	app, err := NewApp(ctx, Client, store, func(c context.Context, _ *State, _ Endpoint, status func(string)) error {
		status("test runtime")
		<-c.Done()
		return nil
	})
	require.NoError(t, err)
	defer app.Close()
	httpServer := httptest.NewServer(app.Handler())
	defer httpServer.Close()
	request := func(method, path string, payload any, auth bool, origin string) int {
		var body io.Reader
		if payload != nil {
			b, err := json.Marshal(payload)
			require.NoError(t, err)
			body = bytes.NewReader(b)
		}
		r, err := http.NewRequest(method, httpServer.URL+path, body)
		require.NoError(t, err)
		if auth {
			r.Header.Set("Authorization", "Bearer "+app.token)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		res, err := http.DefaultClient.Do(r)
		require.NoError(t, err)
		defer res.Body.Close()
		return res.StatusCode
	}
	require.Equal(t, http.StatusUnauthorized, request("GET", "/api/status", nil, false, ""))
	require.Equal(t, http.StatusForbidden, request("POST", "/api/setup", map[string]any{}, true, "http://evil.invalid"))
	state := testClientState()
	code, err := state.Pairing()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, request("POST", "/api/setup", map[string]any{"ip": "127.0.0.1", "port": 17000, "pairing": code}, true, ""))
	loaded, _, err := store.Load()
	require.NoError(t, err)
	require.Equal(t, state, loaded)
	disk, err := os.ReadFile(filepath.Join(store.StateDir, "settings.enc"))
	require.NoError(t, err)
	require.NotContains(t, string(disk), state.AuthToken)
	require.Equal(t, http.StatusOK, request("GET", "/api/status", nil, true, ""))
	cancel()
}
