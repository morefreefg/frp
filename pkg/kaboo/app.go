// Copyright 2026 The frp Authors
// SPDX-License-Identifier: Apache-2.0

package kaboo

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fatedier/frp/pkg/kaboo/trust"
	"github.com/fatedier/frp/pkg/kaboo/vault"
	frplog "github.com/fatedier/frp/pkg/util/log"
)

var BuildVersion = "0.1.0-dev"
var BuildCommit = "development"

const SourceURL = "https://github.com/morefreefg/frp"

//go:embed web/*
var webFiles embed.FS

type Runner func(context.Context, *State, Endpoint, func(string)) error

type App struct {
	role          string
	store         *Store
	run           Runner
	token         string
	ctx           context.Context
	mu            sync.Mutex
	state         *State
	endpoint      Endpoint
	status        string
	generation    uint64
	runtimeCancel context.CancelFunc
	runtimeDone   chan struct{}
}

func NewApp(ctx context.Context, role string, store *Store, run Runner) (*App, error) {
	state, ep, err := store.Load()
	if err != nil {
		return nil, err
	}
	a := &App{role: role, store: store, run: run, ctx: ctx, state: state, endpoint: ep, token: base64.RawURLEncoding.EncodeToString(vault.RandomKey()), status: "等待首次初始化"}
	return a, nil
}

func (a *App) Start() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state != nil {
		a.startLocked()
	}
}
func (a *App) Close() {
	a.mu.Lock()
	cancel, done := a.runtimeCancel, a.runtimeDone
	a.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

func (a *App) startLocked() {
	previous := a.runtimeDone
	if a.runtimeCancel != nil {
		a.runtimeCancel()
	}
	ctx, cancel := context.WithCancel(a.ctx)
	done := make(chan struct{})
	a.runtimeCancel = cancel
	a.runtimeDone = done
	a.generation++
	generation := a.generation
	state := *a.state
	endpoint := a.endpoint
	a.status = "正在启动"
	go func() {
		defer close(done)
		if previous != nil {
			select {
			case <-previous:
			case <-ctx.Done():
				return
			}
		}
		if ctx.Err() != nil {
			return
		}
		update := func(status string) {
			a.mu.Lock()
			defer a.mu.Unlock()
			if a.generation == generation {
				a.status = status
			}
		}
		if err := a.run(ctx, &state, endpoint, update); err != nil && ctx.Err() == nil {
			update("启动或运行失败，请检查地址和端口")
			log.Printf("kaboo runtime: %v", err)
		}
	}()
}

func (a *App) Handler() http.Handler {
	assets, _ := fs.Sub(webFiles, "web")
	static := http.FileServer(http.FS(assets))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			http.Error(w, "Loopback host required", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && origin != "http://"+r.Host {
			http.Error(w, "Origin rejected", http.StatusForbidden)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			if r.Method != http.MethodGet {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			static.ServeHTTP(w, r)
			return
		}
		provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(provided), []byte(a.token)) != 1 {
			http.Error(w, "Open the Web URL printed by the running program", http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/api/status" && r.Method == http.MethodGet:
			a.getStatus(w)
		case r.URL.Path == "/api/setup" && r.Method == http.MethodPost:
			a.setup(w, r)
		case r.URL.Path == "/api/pairing" && r.Method == http.MethodPost:
			a.getPairing(w)
		default:
			http.NotFound(w, r)
		}
	})
}

func respond(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (a *App) getStatus(w http.ResponseWriter) {
	a.mu.Lock()
	defer a.mu.Unlock()
	port := 8388
	if a.state != nil {
		port = a.state.SSPort
	}
	respond(w, map[string]any{"role": a.role, "configured": a.state != nil, "endpoint": a.endpoint, "ssPort": port, "method": SSMethod, "status": a.status,
		"version": BuildVersion, "commit": BuildCommit, "source": SourceURL, "trust": trust.Fingerprint(), "endpointPath": filepath.Join(a.store.StateDir, "endpoint.json")})
}

type setupRequest struct {
	IP         string `json:"ip"`
	Port       int    `json:"port"`
	SSPort     int    `json:"ssPort"`
	Provision  string `json:"provision"`
	Activation string `json:"activation"`
	Pairing    string `json:"pairing"`
}

func (a *App) setup(w http.ResponseWriter, r *http.Request) {
	var input setupRequest
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil {
		http.Error(w, "Invalid setup request", http.StatusBadRequest)
		return
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		http.Error(w, "Invalid setup request", http.StatusBadRequest)
		return
	}
	ep := Endpoint{input.IP, input.Port}
	if err := ep.Validate(a.role); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var next *State
	if a.role == Server {
		if a.state == nil {
			key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(input.Activation))
			if err != nil || len(key) != 32 {
				http.Error(w, "部署包解锁码无效", http.StatusBadRequest)
				return
			}
			defer clear(key)
			if input.Provision == "" {
				executable, err := os.Executable()
				if err != nil {
					http.Error(w, "请选择私钥部署包", http.StatusBadRequest)
					return
				}
				bundle, err := readLimited(filepath.Join(filepath.Dir(executable), "kaboo-server.provision.enc"))
				if err != nil {
					http.Error(w, "请选择私钥部署包", http.StatusBadRequest)
					return
				}
				input.Provision = string(bundle)
			}
			private, err := vault.Open([]byte(input.Provision), key, "deployment-private-key")
			if err != nil {
				http.Error(w, "部署包或解锁码错误", http.StatusBadRequest)
				return
			}
			defer clear(private)
			if _, err := trust.ServerConfig(private); err != nil {
				http.Error(w, "部署包与此程序的内置证书不匹配", http.StatusBadRequest)
				return
			}
			next = &State{Version: 1, Role: Server, PrivateKey: string(private), AuthToken: base64.RawURLEncoding.EncodeToString(vault.RandomKey()), SSPassword: base64.RawURLEncoding.EncodeToString(vault.RandomKey())}
		} else {
			copy := *a.state
			next = &copy
		}
		next.SSPort = input.SSPort
	} else {
		if input.Pairing != "" {
			var err error
			next, err = parsePairing(strings.TrimSpace(input.Pairing))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		} else if a.state != nil {
			copy := *a.state
			next = &copy
		} else {
			http.Error(w, "请导入服务端生成的配对码", http.StatusBadRequest)
			return
		}
	}
	if err := a.store.Save(next, ep); err != nil {
		log.Printf("kaboo configuration save failed: %v", err)
		http.Error(w, "配置无效或无法加密保存，请检查端口和目录权限", http.StatusBadRequest)
		return
	}
	a.state = next
	a.endpoint = ep
	a.startLocked()
	respond(w, map[string]any{"saved": true})
}

func (a *App) getPairing(w http.ResponseWriter) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state == nil {
		http.Error(w, "请先初始化", http.StatusConflict)
		return
	}
	code := ""
	if a.role == Server {
		var err error
		code, err = a.state.Pairing()
		if err != nil {
			http.Error(w, "Cannot export pairing", http.StatusInternalServerError)
			return
		}
	}
	credential := base64.RawURLEncoding.EncodeToString([]byte(SSMethod + ":" + a.state.SSPassword))
	host := a.endpoint.IP
	if host == "0.0.0.0" || host == "::" {
		host = "SERVER_IP"
	}
	uri := "ss://" + credential + "@" + net.JoinHostPort(host, fmt.Sprint(a.state.SSPort)) + "#Kaboo"
	respond(w, map[string]any{"pairing": code, "ssURL": uri, "password": a.state.SSPassword, "method": SSMethod, "port": a.state.SSPort})
}

func Main(role string, run Runner) {
	name := "kaboo-cli"
	port := 17652
	if role == Server {
		name = "kaboo-server"
		port = 17651
	}
	log.SetFlags(log.LstdFlags)
	level := os.Getenv("KABOO_LOG_LEVEL")
	if level == "" {
		level = "info"
	}
	frplog.InitLogger("console", level, 3, true)
	log.Printf("%s %s (%s), based on frp; source: %s", name, BuildVersion, BuildCommit, SourceURL)
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, name+" accepts no command-line arguments; use its local Web interface")
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	store, err := DefaultStore(role)
	if err != nil {
		log.Fatal(err)
	}
	app, err := NewApp(ctx, role, store, run)
	if err != nil {
		log.Fatalf("Cannot load encrypted settings (files were preserved): %v", err)
	}
	defer app.Close()
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
	if err != nil {
		listener, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		log.Fatal(err)
	}
	web := &http.Server{Handler: app.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	log.Printf("Web: http://%s/#token=%s", listener.Addr(), app.token)
	log.Printf("Endpoint file: %s", filepath.Join(store.StateDir, "endpoint.json"))
	app.Start()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = web.Shutdown(shutdown)
	}()
	if err := web.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("Web server: %v", err)
	}
}
