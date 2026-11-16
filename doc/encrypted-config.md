# Encrypted configuration fork

This fork of [fatedier/frp](https://github.com/fatedier/frp) adds authenticated
encryption for configuration at rest and a server configuration editor. It keeps
the upstream protocol, names, command-line options, copyright and license.
It does not provide detection evasion or a guarantee about security scanners.

## Files and keys

Both `frps` and `frpc` use AES-256-GCM with a fresh random 96-bit nonce per save.
The versioned `FRP-CONFIG-V1` envelope is authenticated. The encryption key is a
random 32-byte value, supplied independently through an owner-only key file.
No key is embedded in the programs or the encrypted configuration.

```sh
umask 077
./frps config keygen --output /secure/location/server.key
export FRP_CONFIG_KEY_FILE=/secure/location/server.key

# Input can also be piped through stdin, without a plaintext file on disk.
./frps config encrypt --input server.yaml --output server.yaml.enc
./frps --config server.yaml.enc
```

On the client, generate a separate local encryption key:

```sh
./frpc config keygen --output /secure/location/client.key
export FRP_CONFIG_KEY_FILE=/secure/location/client.key
./frpc config encrypt --input client.yaml --output client.yaml.enc
./frpc --config client.yaml.enc
```

Retain the original YAML field names and nesting. For example:

```yaml
# server.yaml: fill in your own passwords and shared token before encrypting.
bindAddr: 0.0.0.0
bindPort: 7000
auth:
  method: token
  token: REPLACE_WITH_A_RANDOM_SHARED_TOKEN
webServer:
  addr: 127.0.0.1
  port: 7500
  user: admin
  password: REPLACE_WITH_A_RANDOM_DASHBOARD_PASSWORD
```

```yaml
# client.yaml: auth.token must match the server, encryption keys need not match.
serverAddr: YOUR_SERVER_ADDRESS
serverPort: 7000
auth:
  method: token
  token: REPLACE_WITH_A_RANDOM_SHARED_TOKEN
webServer:
  addr: 127.0.0.1
  port: 7400
  user: admin
  password: REPLACE_WITH_A_RANDOM_DASHBOARD_PASSWORD
store:
  path: rules.json.enc
proxies:
  - name: example
    type: tcp
    localIP: 127.0.0.1
    localPort: 8080
    remotePort: 18080
```

Use YAML instead of the deprecated INI format for new deployments. TOML and JSON
also work, including `.toml.enc` and `.json.enc`. Existing plaintext deployments
continue to work when encrypted mode is not selected. Setting
`FRP_CONFIG_KEY_FILE` enables strict encrypted mode: main configuration, included
configuration files, and existing Store files must all be encrypted. A missing
Store is created encrypted on the first Web rule save. To migrate an existing
Store, stop the client and encrypt its JSON with `config encrypt` first, then
update `store.path` in the main configuration.

The encryption command refuses to overwrite an existing output or key file.
Missing keys, unsafe key permissions, corruption and plaintext input in strict
mode fail closed. Saving an existing encrypted file cannot downgrade it to
plaintext if the key environment variable is accidentally removed. Saves use
an owner-only temporary file containing ciphertext and an atomic rename.

Encryption does not remove plaintext input files passed to `--input`; handle
those separately. For a new deployment, use stdin or pipe configuration directly
from your secret manager rather than creating a plaintext YAML file. Normal
file deletion does not guarantee secure erasure on SSDs or snapshots.

## Web management

The programs embed both upstream dashboards; no separate web server is required.

- Client: `http://127.0.0.1:7400/`, then **Config** or the existing graphical
  proxy/visitor editor. Config and Store writes both remain encrypted in encrypted
  mode. The Config editor validates syntax and values before saving, then uses
  upstream client reload behavior. Some common/client connection settings still
  require restarting frpc; reload primarily updates proxy and visitor rules.
- Server: `http://127.0.0.1:7500/`, then **Configuration**. Edit the original
  YAML/TOML/JSON, save, and explicitly restart frps to apply changes. The server
  editor checks revisions and rejects an outdated save with HTTP 409. It is
  enabled only for a file-backed server with dashboard username and password.
- Encrypted configurations require dashboard credentials whenever `webServer`
  is enabled. Configuration read responses use `Cache-Control: no-store`.

Keep dashboards on loopback and reach them through an authenticated SSH tunnel,
or configure HTTPS. The editor necessarily displays decrypted secrets to the
authenticated administrator. Encryption at rest does not replace HTTPS.

## Security boundary and operations

The key file itself is a secret, not a password-protected vault. Put it outside
the configuration directory, restrict access, and prefer delivery from an OS
credential service into a volatile file (for example, systemd credentials on
Linux). Do not distribute a key with the encrypted configuration or in Git.
Back up keys independently; losing the key makes the configuration unrecoverable.
Runtime memory and the authenticated editor contain plaintext. This design does
not protect against root, process-memory access, or an attacker able to read
both the ciphertext and key. External certificate/private-key files, tokenSource
files, plugin data, operating-system swap/core dumps and external log files are
outside the configuration-envelope scope. Avoid debug logs containing secrets.

This is a custom extension and has not had an independent cryptographic audit.
Use up-to-date operating systems and Go toolchains. Keep a separate key per
installation and rotate by decrypting in memory, re-encrypting all configuration
and Store files with a new key, and restarting the service. A built-in key rotation
or recovery UI is not provided in this version.

## Build and verification

The fork currently starts from upstream development commit `a2c975ef` (version
0.72.0). Build web assets with the repository's locked npm dependencies before
building binaries:

```sh
cd web
npm ci
npm run build --workspace frps
npm run build --workspace frpc
cd ..
./hack/build-encrypted.sh /absolute/path/to/output
```

This produces Linux amd64 and macOS arm64 packages, each with both programs,
this guide, the upstream license, and SHA-256 checksums. Build metadata preserves
the upstream origin and adds an `encrypted.1` version suffix and source revision.

```sh
go test -race -tags noweb ./pkg/config/... ./client/... ./server/... ./cmd/...
```

New tests cover tampering, wrong/missing keys, random nonces, private key
permissions, refusal of plaintext includes, encrypted Store reload/rollback,
client invalid-save preservation, and server edit validation/revision conflicts.
