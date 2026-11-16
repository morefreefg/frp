// Copyright 2026 The frp Authors
// SPDX-License-Identifier: Apache-2.0

// kaboo-provision is an offline build tool, not a runtime daemon.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/fatedier/frp/pkg/kaboo/vault"
)

func main() {
	trust := flag.String("trust", "", "public certificate destination")
	provision := flag.String("provision", "", "encrypted private-key bundle destination")
	activation := flag.String("activation", "", "separate activation key destination")
	flag.Parse()
	if *trust == "" || *provision == "" || *activation == "" {
		panic("all three destinations are required")
	}
	for _, p := range []string{*trust, *provision, *activation} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			panic("destination exists or cannot be inspected: " + p)
		}
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	must(err)
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Kaboo deployment trust"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0), DNSNames: []string{"kaboo-server"},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, private)
	must(err)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(private)
	must(err)
	plain := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	defer clear(plain)
	defer clear(pkcs8)
	defer clear(private)
	key := vault.RandomKey()
	defer clear(key)
	sealed, err := vault.Seal(plain, key, "deployment-private-key")
	must(err)
	for _, p := range []string{*trust, *provision, *activation} {
		must(os.MkdirAll(filepath.Dir(p), 0o700))
	}
	must(os.WriteFile(*trust, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644))
	must(os.WriteFile(*provision, sealed, 0o600))
	must(os.WriteFile(*activation, []byte(base64.StdEncoding.EncodeToString(key)+"\n"), 0o600))
	fingerprint := sha256.Sum256(der)
	fmt.Printf("Generated public deployment certificate: sha256:%x\nPrivate bundle and activation key are separate; neither belongs in Git.\n", fingerprint)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
