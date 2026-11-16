// Copyright 2026 The frp Authors
// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"
)

// Certificate is public. Private key material must never be embedded here.
//
//go:embed ca.pem
var Certificate []byte

func ClientConfig() *tls.Config {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(Certificate) {
		panic("invalid embedded trust certificate")
	}
	return &tls.Config{RootCAs: pool, ServerName: "kaboo-server", MinVersion: tls.VersionTLS13, NextProtos: []string{"kaboo/1"}}
}

func ServerConfig(private []byte) (*tls.Config, error) {
	pair, err := tls.X509KeyPair(Certificate, private)
	if err != nil {
		return nil, errors.New("private key does not match this build's embedded certificate")
	}
	return &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13, NextProtos: []string{"kaboo/1"}}, nil
}

func Fingerprint() string {
	b, _ := pem.Decode(Certificate)
	if b == nil {
		return "invalid"
	}
	sum := sha256.Sum256(b.Bytes)
	return fmt.Sprintf("sha256:%x", sum)
}
