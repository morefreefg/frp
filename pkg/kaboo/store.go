// Copyright 2026 The frp Authors
// SPDX-License-Identifier: Apache-2.0

package kaboo

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatedier/frp/pkg/config/securefile"
	"github.com/fatedier/frp/pkg/kaboo/trust"
	"github.com/fatedier/frp/pkg/kaboo/vault"
)

const (
	Client   = "client"
	Server   = "server"
	SSMethod = "aes-256-gcm"
)

type Endpoint struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

type State struct {
	Version    int    `json:"version"`
	Role       string `json:"role"`
	AuthToken  string `json:"tunnelKey"`
	SSPassword string `json:"ssPassword"`
	SSPort     int    `json:"ssPort"`
	PrivateKey string `json:"serverPrivateKey,omitempty"`
}

type pairing struct {
	Version    int    `json:"version"`
	Trust      string `json:"trust"`
	AuthToken  string `json:"tunnelKey"`
	SSPassword string `json:"ssPassword"`
	SSPort     int    `json:"ssPort"`
}

type Store struct {
	StateDir string
	KeyDir   string
	Role     string
}

func DefaultStore(role string) (*Store, error) {
	if home := os.Getenv("KABOO_HOME"); home != "" {
		return &Store{filepath.Join(home, "state"), filepath.Join(home, "private"), role}, nil
	}
	config, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	return &Store{filepath.Join(config, "kaboo", role), filepath.Join(config, "kaboo-private", role), role}, nil
}

func (e Endpoint) Validate(role string) error {
	if e.Port < 1 || e.Port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	if net.ParseIP(e.IP) == nil {
		if role == Server {
			return errors.New("server IP must be a literal bind address")
		}
		if len(e.IP) == 0 || len(e.IP) > 253 || strings.ContainsAny(e.IP, " /:\r\n\t") {
			return errors.New("invalid server address")
		}
	}
	return nil
}

func (s *Store) Load() (*State, Endpoint, error) {
	data, err := readLimited(filepath.Join(s.StateDir, "settings.enc"))
	if os.IsNotExist(err) {
		return nil, Endpoint{IP: "127.0.0.1", Port: 7000}, nil
	}
	if err != nil {
		return nil, Endpoint{}, err
	}
	key, err := s.key(false)
	if err != nil {
		return nil, Endpoint{}, err
	}
	defer clear(key)
	plain, err := vault.Open(data, key, "settings:"+s.Role)
	if err != nil {
		return nil, Endpoint{}, err
	}
	defer clear(plain)
	var state State
	if err := json.Unmarshal(plain, &state); err != nil {
		return nil, Endpoint{}, errors.New("invalid encrypted settings")
	}
	if err := state.Validate(s.Role); err != nil {
		return nil, Endpoint{}, err
	}
	endpointData, err := readLimited(filepath.Join(s.StateDir, "endpoint.json"))
	if err != nil {
		return nil, Endpoint{}, err
	}
	endpoint, err := parseEndpoint(endpointData, s.Role)
	if err != nil {
		return nil, Endpoint{}, err
	}
	return &state, endpoint, nil
}

func parseEndpoint(data []byte, role string) (Endpoint, error) {
	var e Endpoint
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&e); err != nil {
		return e, errors.New("endpoint.json accepts only ip and port")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return e, errors.New("invalid endpoint document")
	}
	return e, e.Validate(role)
}

func (s *State) Validate(role string) error {
	if s.Version != 1 || s.Role != role || len(s.AuthToken) < 32 || len(s.SSPassword) < 32 || s.SSPort < 1 || s.SSPort > 65535 {
		return errors.New("invalid Kaboo settings")
	}
	if role == Server {
		_, err := trust.ServerConfig([]byte(s.PrivateKey))
		return err
	}
	if s.PrivateKey != "" {
		return errors.New("client settings must not contain a server private key")
	}
	return nil
}

func (s *Store) Save(state *State, e Endpoint) error {
	if err := state.Validate(s.Role); err != nil {
		return err
	}
	if err := e.Validate(s.Role); err != nil {
		return err
	}
	if s.Role == Server && e.Port == state.SSPort {
		return errors.New("tunnel and Shadowsocks ports must differ")
	}
	if err := os.MkdirAll(s.StateDir, 0o700); err != nil {
		return err
	}
	key, err := s.key(true)
	if err != nil {
		return err
	}
	defer clear(key)
	plain, err := json.Marshal(state)
	if err != nil {
		return err
	}
	defer clear(plain)
	sealed, err := vault.Seal(plain, key, "settings:"+s.Role)
	if err != nil {
		return err
	}
	if err := securefile.AtomicWrite(filepath.Join(s.StateDir, "settings.enc"), sealed); err != nil {
		return err
	}
	return s.SaveEndpoint(e)
}

func (s *Store) SaveEndpoint(e Endpoint) error {
	if err := e.Validate(s.Role); err != nil {
		return err
	}
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	return securefile.AtomicWrite(filepath.Join(s.StateDir, "endpoint.json"), append(b, '\n'))
}

func (s *Store) key(create bool) ([]byte, error) {
	path := filepath.Join(s.KeyDir, "master.key")
	if create {
		if err := os.MkdirAll(s.KeyDir, 0o700); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			key := vault.RandomKey()
			_, err = f.Write(key)
			clear(key)
			closeErr := f.Close()
			if err != nil {
				return nil, err
			}
			if closeErr != nil {
				return nil, closeErr
			}
		} else if !os.IsExist(err) {
			return nil, err
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open local encryption key: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("local encryption key must be owner-only")
	}
	key, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil || len(key) != 32 {
		return nil, errors.New("invalid local encryption key")
	}
	return key, nil
}

func readLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, (2<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 2<<20 {
		return nil, errors.New("file too large")
	}
	return b, nil
}

func (s *State) Pairing() (string, error) {
	b, err := json.Marshal(pairing{1, trust.Fingerprint(), s.AuthToken, s.SSPassword, s.SSPort})
	if err != nil {
		return "", err
	}
	return "kaboo://" + base64.RawURLEncoding.EncodeToString(b), nil
}

func parsePairing(code string) (*State, error) {
	if !strings.HasPrefix(code, "kaboo://") || len(code) > 8192 {
		return nil, errors.New("invalid pairing code")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(code, "kaboo://"))
	if err != nil {
		return nil, errors.New("invalid pairing code")
	}
	var p pairing
	if err := json.Unmarshal(b, &p); err != nil || p.Version != 1 || p.Trust != trust.Fingerprint() {
		return nil, errors.New("pairing code is for a different certificate/build")
	}
	s := &State{Version: 1, Role: Client, AuthToken: p.AuthToken, SSPassword: p.SSPassword, SSPort: p.SSPort}
	return s, s.Validate(Client)
}
