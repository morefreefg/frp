// Copyright 2026 The frp Authors
// SPDX-License-Identifier: Apache-2.0
//go:build !frpc

package kaboo

import (
	"context"

	"github.com/fatedier/frp/pkg/config/types"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/config/v1/validation"
	"github.com/fatedier/frp/pkg/kaboo/trust"
	"github.com/fatedier/frp/pkg/policy/security"
	"github.com/fatedier/frp/server"
)

func RunServer(ctx context.Context, state *State, endpoint Endpoint, status func(string)) error {
	tlsConfig, err := trust.ServerConfig([]byte(state.PrivateKey))
	if err != nil {
		return err
	}
	cfg := &v1.ServerConfig{BindAddr: endpoint.IP, BindPort: endpoint.Port, ProxyBindAddr: endpoint.IP,
		AllowPorts: []types.PortsRange{{Single: state.SSPort}}, MaxPortsPerClient: 2, UDPPacketSize: 65507}
	cfg.Auth.Method = "token"
	cfg.Auth.Token = state.AuthToken
	cfg.Auth.AdditionalScopes = []v1.AuthScope{"HeartBeats", "NewWorkConns"}
	cfg.Transport.TCPMux = new(false)
	cfg.Transport.TLS.Force = true
	if err := cfg.Complete(); err != nil {
		return err
	}
	if _, err := validation.NewConfigValidator(security.NewUnsafeFeatures(nil)).ValidateServerConfig(cfg); err != nil {
		return err
	}
	svc, err := server.NewService(cfg, server.WithTLSConfig(tlsConfig))
	if err != nil {
		return err
	}
	status("服务端运行中；SS 入口在客户端在线时可用")
	svc.Run(ctx)
	return nil
}
