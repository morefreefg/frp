# Kaboo third-party components

Kaboo uses the upstream frp core and retains its attribution, source metadata
and Apache License 2.0. The full license is included as `LICENSE` in each package.

The new embedded Shadowsocks component uses:

- [shadowsocks/go-shadowsocks2](https://github.com/shadowsocks/go-shadowsocks2),
  version v0.1.5, Apache License 2.0. The library's AEAD stream and packet APIs
  provide standard Shadowsocks `aes-256-gcm` encryption and salt replay checks.
- [riobard/go-bloom](https://github.com/riobard/go-bloom), version
  v0.0.0-20200614022211-cdc8013cb5b3, Apache License 2.0, used by that library.

Other frp dependencies and their exact locked versions remain listed in
[`go.mod`](https://github.com/morefreefg/frp/blob/dev/go.mod) and the Go build
metadata of each binary. No source or private signing key is concealed in the
Kaboo product name.
