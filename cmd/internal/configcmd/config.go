// Copyright 2026 The frp Authors
// SPDX-License-Identifier: Apache-2.0

package configcmd

import (
	"errors"
	"github.com/fatedier/frp/pkg/config/securefile"
	"github.com/spf13/cobra"
	"io"
	"os"
)

func New() *cobra.Command {
	root := &cobra.Command{Use: "config", Short: "Manage encrypted configuration files"}
	var keyOutput string
	key := &cobra.Command{Use: "keygen", Short: "Create an owner-only random encryption key", Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error { return securefile.GenerateKey(keyOutput) }}
	key.Flags().StringVar(&keyOutput, "output", "", "new key file path (must not exist)")
	_ = key.MarkFlagRequired("output")
	var input, output string
	seal := &cobra.Command{Use: "encrypt", Short: "Encrypt YAML/TOML/JSON without a plaintext temporary file", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := os.Lstat(output); err == nil {
				return errors.New("output already exists; choose a new path")
			} else if !os.IsNotExist(err) {
				return err
			}
			r := cmd.InOrStdin()
			if input != "-" {
				f, err := os.Open(input)
				if err != nil {
					return err
				}
				defer f.Close()
				r = f
			}
			b, err := io.ReadAll(io.LimitReader(r, securefile.MaxSize+1))
			if err != nil {
				return err
			}
			defer clear(b)
			if securefile.IsEncrypted(b) {
				return errors.New("input is already encrypted")
			}
			enc, err := securefile.Encrypt(b)
			if err != nil {
				return err
			}
			f, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return err
			}
			_, err = f.Write(enc)
			closeErr := f.Close()
			if err != nil {
				os.Remove(output)
				return err
			}
			return closeErr
		}}
	seal.Flags().StringVar(&input, "input", "-", "plaintext input file, or - for stdin")
	seal.Flags().StringVar(&output, "output", "", "new encrypted file path (e.g. frpc.yaml.enc)")
	_ = seal.MarkFlagRequired("output")
	root.AddCommand(key, seal)
	return root
}
