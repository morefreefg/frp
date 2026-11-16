// Copyright 2026 The frp Authors
// SPDX-License-Identifier: Apache-2.0

// Package securefile protects configuration at rest. It does not change the
// network protocol or conceal the identity of the program.
package securefile

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const KeyFileEnv = "FRP_CONFIG_KEY_FILE"
const MaxSize = 8 << 20
const magic = "FRP-CONFIG-V1\n"

func Enabled() bool                { return os.Getenv(KeyFileEnv) != "" }
func IsEncrypted(data []byte) bool { return bytes.HasPrefix(data, []byte(magic)) }

func readKey() ([]byte, error) {
	path := os.Getenv(KeyFileEnv)
	if path == "" {
		return nil, fmt.Errorf("set %s to a private key file", KeyFileEnv)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open configuration key: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return nil, errors.New("configuration key must be a regular file accessible only by its owner (0600)")
	}
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(b) > 4096 {
		return nil, errors.New("cannot read configuration key")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(key) != 32 {
		return nil, errors.New("configuration key must contain a base64-encoded random 32-byte key")
	}
	return key, nil
}

func aead() (cipher.AEAD, error) {
	key, err := readKey()
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func Encrypt(data []byte) ([]byte, error) {
	if len(data) > MaxSize {
		return nil, errors.New("configuration exceeds 8 MiB")
	}
	a, err := aead()
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(magic)+a.NonceSize())
	copy(out, magic)
	nonce := out[len(magic):]
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return a.Seal(out, nonce, data, []byte(magic)), nil
}

func Decrypt(data []byte) ([]byte, error) {
	if !IsEncrypted(data) {
		return nil, errors.New("not an encrypted configuration")
	}
	a, err := aead()
	if err != nil {
		return nil, err
	}
	if len(data) < len(magic)+a.NonceSize()+a.Overhead() || len(data) > MaxSize+len(magic)+a.NonceSize()+a.Overhead() {
		return nil, errors.New("invalid encrypted configuration size")
	}
	nonce := data[len(magic) : len(magic)+a.NonceSize()]
	plain, err := a.Open(nil, nonce, data[len(magic)+a.NonceSize():], []byte(magic))
	if err != nil {
		return nil, errors.New("configuration authentication failed: wrong key or damaged file")
	}
	return plain, nil
}

func ReadFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxSize+1024))
	if err != nil {
		return nil, err
	}
	if IsEncrypted(b) {
		return Decrypt(b)
	}
	if Enabled() || strings.HasSuffix(strings.ToLower(path), ".enc") {
		return nil, errors.New("plaintext configuration refused: encrypt the file before using encrypted mode")
	}
	if len(b) > MaxSize {
		return nil, errors.New("configuration exceeds 8 MiB")
	}
	return b, nil
}

// WriteFile atomically replaces the destination. Encrypted files never fall back
// to plaintext, even if a key has accidentally been removed from the environment.
func WriteFile(path string, data []byte) error {
	encrypt := Enabled() || strings.HasSuffix(strings.ToLower(path), ".enc")
	if !encrypt {
		f, err := os.Open(path)
		if err == nil {
			header := make([]byte, len(magic))
			_, _ = io.ReadFull(f, header)
			f.Close()
			encrypt = IsEncrypted(header)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	if len(data) > MaxSize {
		return errors.New("configuration exceeds 8 MiB")
	}
	if encrypt {
		var err error
		data, err = Encrypt(data)
		if err != nil {
			return err
		}
	}
	return AtomicWrite(path, data)
}

// AtomicWrite writes already-encoded data with owner-only permissions. The
// transient file contains ciphertext whenever encryption is enabled.
func AtomicWrite(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".frp-config-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func GenerateKey(path string) error {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	defer clear(key)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := fmt.Fprintln(f, base64.StdEncoding.EncodeToString(key))
	closeErr := f.Close()
	if writeErr != nil {
		os.Remove(path)
		return writeErr
	}
	return closeErr
}
