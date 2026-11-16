// Copyright 2026 The frp Authors
// SPDX-License-Identifier: Apache-2.0

package server

import "crypto/tls"

// WithTLSConfig supplies an in-memory TLS identity for embedders. Normal frps
// deployments continue to use their existing certificate-file configuration.
func WithTLSConfig(cfg *tls.Config) ServiceOption {
	return func(s *Service) {
		if cfg != nil {
			s.tlsConfig = cfg.Clone()
		}
	}
}
