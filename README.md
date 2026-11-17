# vault-plugin-secrets-arrstack

A HashiCorp Vault / OpenBao secrets engine that mints short-lived **arrproxy
machine tokens** for the *arr apps (Sonarr, Radarr, Prowlarr).

arrproxy fronts the *arr apps behind one authenticated proxy. This engine calls
its bearer-gated admin API to mint a token per request, scoped to a subset of
the apps (and optionally to a set of HTTP methods), and binds each token to a
Vault lease: revoking the lease disables the token in arrproxy.

The same binary runs on Vault and OpenBao; every command below works with
`bao` in place of `vault`.

To manage the engine's mount, config, and roles from Terraform, use
[terraform-provider-vault-secrets-arrstack](https://github.com/IUCLabs/terraform-provider-vault-secrets-arrstack).

## Requirements

- Vault or OpenBao with external plugin support (built against Vault SDK
  v0.14.0; no other versions are tested in this repo)
- An arrproxy instance and its admin bearer token
- Go 1.25+ to build from source

## Installation

Build the binary (or download one from the
[releases page](https://github.com/IUCLabs/vault-plugin-secrets-arrstack/releases))
and copy it into the server's plugin directory. `PLUGIN_DIR` below must match
`plugin_directory` in the server config:

```sh
PLUGIN_DIR=/etc/vault/plugins  # set to your server's plugin_directory
make build                     # writes ./dist/vault-plugin-secrets-arrstack
cp dist/vault-plugin-secrets-arrstack "$PLUGIN_DIR/"
```

Register it in the plugin catalog by its SHA-256, then enable it:

```sh
SHA256=$(sha256sum "$PLUGIN_DIR/vault-plugin-secrets-arrstack" | cut -d' ' -f1)

vault plugin register -sha256="$SHA256" secret vault-plugin-secrets-arrstack
vault secrets enable -path=arrstack vault-plugin-secrets-arrstack
```

## Configuration

Point the engine at arrproxy's admin API:

```sh
vault write arrstack/config \
  base_url=https://arrproxy.example.com \
  admin_token="$ARRPROXY_ADMIN_TOKEN"
```

`admin_token` is never returned on read. Add `ca_cert=@ca.pem` if arrproxy's TLS
certificate is not signed by a CA in the system trust store.

## Usage

Create a role that limits which apps a token can reach and how long it lives:

```sh
vault write arrstack/roles/media apps="sonarr,radarr" ttl=1h max_ttl=24h
```

Mint a token:

```sh
$ vault read arrstack/creds/media
Key                Value
---                -----
lease_id           arrstack/creds/media/AbC...
lease_duration     1h
lease_renewable    true
apps               [radarr sonarr]
expires_at         2026-01-01T13:00:00Z
id                 tok-...
methods            []
subject            vault:arrstack:media
token              arr_...
```

Revoke it early:

```sh
vault lease revoke arrstack/creds/media/AbC...
```

A read-only role pins tokens to safe HTTP methods; arrproxy rejects anything
else with `405`:

```sh
vault write arrstack/roles/sonarr-ro apps="sonarr" methods="GET,HEAD" ttl=1h
```

## Documentation

Full path reference, with every parameter:

- [`config`](docs/config.md) – connection to arrproxy
- [`roles`](docs/roles.md) – token constraints
- [`creds`](docs/creds.md) – minting, renewal, and revocation

## Development

```sh
make build   # build into ./dist
make test    # unit tests
make lint    # go vet
```

## License

[MIT](LICENSE)
