// Copyright 2026 The frp Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/fatedier/frp/pkg/config"
	"github.com/fatedier/frp/pkg/config/securefile"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/config/v1/validation"
	"github.com/fatedier/frp/pkg/policy/security"
)

type ServiceOption func(*Service)

// WithConfigFile enables authenticated editing of a file-backed server config.
// Changes take effect after an explicit service restart.
func WithConfigFile(path string, unsafeFeatures *security.UnsafeFeatures) ServiceOption {
	return func(s *Service) {
		if path != "" && s.cfg.WebServer.User != "" && s.cfg.WebServer.Password != "" {
			s.configEditor = &configFileEditor{path: path, validator: validation.NewConfigValidator(unsafeFeatures)}
		}
	}
}

type configFileEditor struct {
	mu        sync.Mutex
	path      string
	validator *validation.ConfigValidator
}

type configFileDocument struct {
	Content   string `json:"content"`
	Revision  string `json:"revision"`
	Encrypted bool   `json:"encrypted"`
}

func configRevision(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func (e *configFileEditor) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	e.mu.Lock()
	defer e.mu.Unlock()
	content, err := securefile.ReadFile(e.path)
	if err != nil {
		http.Error(w, "Cannot read configuration", http.StatusInternalServerError)
		return
	}
	defer clear(content)
	if r.Method == http.MethodGet {
		_ = json.NewEncoder(w).Encode(configFileDocument{Content: string(content), Revision: configRevision(content), Encrypted: securefile.Enabled()})
		return
	}
	if r.Header.Get("X-FRP-Config") != "1" {
		http.Error(w, "Missing configuration request header", http.StatusForbidden)
		return
	}
	var doc configFileDocument
	r.Body = http.MaxBytesReader(w, r.Body, securefile.MaxSize)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil || len(doc.Content) == 0 {
		http.Error(w, "Invalid configuration request", http.StatusBadRequest)
		return
	}
	if doc.Revision != configRevision(content) {
		http.Error(w, "Configuration changed; reload before saving", http.StatusConflict)
		return
	}
	rendered, err := config.RenderWithTemplate([]byte(doc.Content), config.GetValues())
	if err != nil {
		http.Error(w, "Invalid configuration template", http.StatusBadRequest)
		return
	}
	var cfg v1.ServerConfig
	if err := config.LoadConfigure(rendered, &cfg, true); err != nil {
		http.Error(w, "Invalid configuration syntax or fields", http.StatusBadRequest)
		return
	}
	if err := cfg.Complete(); err != nil {
		http.Error(w, "Invalid configuration values", http.StatusBadRequest)
		return
	}
	if _, err := e.validator.ValidateServerConfig(&cfg); err != nil {
		http.Error(w, "Invalid configuration values", http.StatusBadRequest)
		return
	}
	if cfg.WebServer.Port > 0 && (cfg.WebServer.User == "" || cfg.WebServer.Password == "") {
		http.Error(w, "Configuration editor requires dashboard credentials", http.StatusBadRequest)
		return
	}
	if err := securefile.WriteFile(e.path, []byte(doc.Content)); err != nil {
		http.Error(w, "Cannot save configuration", http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"revision": configRevision([]byte(doc.Content)), "restartRequired": true})
}
