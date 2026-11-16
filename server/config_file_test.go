package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/fatedier/frp/pkg/config/securefile"
	"github.com/fatedier/frp/pkg/config/v1/validation"
	"github.com/fatedier/frp/pkg/policy/security"
	"github.com/stretchr/testify/require"
)

func TestConfigEditorEncryptedSaveAndConflict(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	require.NoError(t, securefile.GenerateKey(key))
	t.Setenv(securefile.KeyFileEnv, key)
	path := filepath.Join(dir, "server.yaml.enc")
	initial := []byte("bindPort: 17000\nauth:\n  token: initial-secret\n")
	require.NoError(t, securefile.WriteFile(path, initial))
	editor := &configFileEditor{path: path, validator: validation.NewConfigValidator(security.NewUnsafeFeatures(nil))}
	get := httptest.NewRecorder()
	editor.serve(get, httptest.NewRequest(http.MethodGet, "/api/config", nil))
	require.Equal(t, http.StatusOK, get.Code)
	require.Equal(t, "no-store", get.Header().Get("Cache-Control"))
	var doc configFileDocument
	require.NoError(t, json.Unmarshal(get.Body.Bytes(), &doc))
	require.True(t, doc.Encrypted)
	doc.Content = "bindPort: 17001\nauth:\n  token: replacement-secret\n"
	body, err := json.Marshal(doc)
	require.NoError(t, err)
	put := func(header bool, payload []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPut, "/api/config", bytes.NewReader(payload))
		if header {
			r.Header.Set("X-FRP-Config", "1")
		}
		w := httptest.NewRecorder()
		editor.serve(w, r)
		return w
	}
	require.Equal(t, http.StatusForbidden, put(false, body).Code)
	require.Equal(t, http.StatusOK, put(true, body).Code)
	onDisk, err := os.ReadFile(path)
	require.NoError(t, err)
	require.True(t, securefile.IsEncrypted(onDisk))
	require.NotContains(t, string(onDisk), "replacement-secret")
	plain, err := securefile.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, doc.Content, string(plain))
	require.Equal(t, http.StatusConflict, put(true, body).Code)
	doc.Revision = configRevision(plain)
	doc.Content = "bindPort: invalid-value"
	body, err = json.Marshal(doc)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, put(true, body).Code)
	still, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, onDisk, still)
}
