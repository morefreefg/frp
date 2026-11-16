// Copyright 2026 The frp Authors
// SPDX-License-Identifier: Apache-2.0

// Package vault stores Kaboo settings separately from the public endpoint file.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
)

type envelope struct {
	Version int    `json:"kabooVault"`
	Kind    string `json:"kind"`
	Nonce   string `json:"nonce"`
	Data    string `json:"data"`
}

func RandomKey() []byte { b := make([]byte, 32); _, _ = rand.Read(b); return b }

func aead(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid vault key length")
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func Seal(plain, key []byte, kind string) ([]byte, error) {
	a, err := aead(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, a.NonceSize())
	_, _ = rand.Read(nonce)
	ciphertext := a.Seal(nil, nonce, plain, []byte("kaboo-vault-v1:"+kind))
	return json.Marshal(envelope{1, kind, base64.StdEncoding.EncodeToString(nonce), base64.StdEncoding.EncodeToString(ciphertext)})
}

func Open(data, key []byte, kind string) ([]byte, error) {
	if len(data) > 2<<20 {
		return nil, errors.New("vault is too large")
	}
	var e envelope
	if err := json.Unmarshal(data, &e); err != nil || e.Version != 1 || e.Kind != kind {
		return nil, errors.New("invalid vault format or purpose")
	}
	a, err := aead(key)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(e.Nonce)
	if err != nil || len(nonce) != a.NonceSize() {
		return nil, errors.New("invalid vault nonce")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(e.Data)
	if err != nil {
		return nil, errors.New("invalid vault data")
	}
	plain, err := a.Open(nil, nonce, ciphertext, []byte("kaboo-vault-v1:"+kind))
	if err != nil {
		return nil, errors.New("vault authentication failed")
	}
	return plain, nil
}
