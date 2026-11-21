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

Release assets download through artifactapi's GitHub proxy, which serves
`https://artifactapi.k8s.syd1.au.unkin.net/api/v1/remote/github/IUCLabs/vault-plugin-secrets-arrstack/releases/download/<tag>/<file>`.
Each method below ends with `SHA256` set for [registration](#register-and-enable).
With OpenBao, use `bao` in place of `vault`.

```sh
TAG=vX.Y.Z  # the release to install
V=${TAG#v}
BASE=https://artifactapi.k8s.syd1.au.unkin.net/api/v1/remote/github/IUCLabs/vault-plugin-secrets-arrstack/releases/download/$TAG
```

### RPM

`vault-plugin-secrets-arrstack` installs `/usr/libexec/vault-plugins/vault-plugin-secrets-arrstack`;
`openbao-plugin-secrets-arrstack` installs it in `/usr/libexec/openbao-plugins/`.
Set the server's `plugin_directory` to that directory.

```sh
dnf install vault-plugin-secrets-arrstack  # from a yum repo carrying it, or from the release:
dnf install "$BASE/vault-plugin-secrets-arrstack-$V-1.x86_64.rpm"  # openbao-plugin-secrets-arrstack-$V-1.x86_64.rpm for OpenBao

SHA256=$(sha256sum /usr/libexec/vault-plugins/vault-plugin-secrets-arrstack | cut -d' ' -f1)
```

### Released binary

`vault-plugin-secrets-arrstack_<version>_SHA256SUMS` lists the binary and the RPMs, and
`SHA256SUMS.sig` is its detached signature by the IUCLabs release GPG key.

```sh
curl -fLO "$BASE/vault-plugin-secrets-arrstack_${V}_linux_amd64"
curl -fLO "$BASE/vault-plugin-secrets-arrstack_${V}_SHA256SUMS"
curl -fLO "$BASE/vault-plugin-secrets-arrstack_${V}_SHA256SUMS.sig"
gpg --verify "vault-plugin-secrets-arrstack_${V}_SHA256SUMS.sig" "vault-plugin-secrets-arrstack_${V}_SHA256SUMS"
sha256sum --check --ignore-missing "vault-plugin-secrets-arrstack_${V}_SHA256SUMS"

install -m 0755 "vault-plugin-secrets-arrstack_${V}_linux_amd64" <plugin_directory>/vault-plugin-secrets-arrstack
SHA256=$(sha256sum <plugin_directory>/vault-plugin-secrets-arrstack | cut -d' ' -f1)
```

### Kubernetes image volume

`ghcr.io/iuclabs/vault-plugin-secrets-arrstack:<tag>` is a `FROM scratch` image holding only
`/vault-plugin-secrets-arrstack`. Mount it read-only into the Vault/OpenBao container with an
[image volume](https://kubernetes.io/docs/concepts/storage/volumes/#image):
Kubernetes 1.31+ with the `ImageVolume` feature gate (beta, on by default from
1.33). Vault and OpenBao only run a binary that sits directly in
`plugin_directory`, not in a subdirectory, so mount the file itself with
`subPath`, which on image volumes needs 1.33+.

```yaml
spec:
  containers:
    - name: vault
      volumeMounts:
        - name: plugin-arrstack
          mountPath: /vault/plugins/vault-plugin-secrets-arrstack  # <plugin_directory>/vault-plugin-secrets-arrstack
          subPath: vault-plugin-secrets-arrstack
          readOnly: true
  volumes:
    - name: plugin-arrstack
      image:
        reference: ghcr.io/iuclabs/vault-plugin-secrets-arrstack:vX.Y.Z
        pullPolicy: IfNotPresent
```

The image holds the released binary, so its sha256 is the `linux_amd64` line
of `SHA256SUMS`:

```sh
SHA256=$(curl -fsSL "$BASE/vault-plugin-secrets-arrstack_${V}_SHA256SUMS" | awk '/_linux_amd64$/ {print $1}')
```

### From source

```sh
make build  # writes ./dist/vault-plugin-secrets-arrstack
```

Copy it into `plugin_directory` and take `SHA256` from `sha256sum` as above.

### Register and enable

```sh
vault plugin register -sha256="$SHA256" secret vault-plugin-secrets-arrstack
vault secrets enable -path=arrstack vault-plugin-secrets-arrstack
```

After replacing the binary, register the new sha256 and reload the plugin:

```sh
vault write sys/plugins/reload/backend plugin=vault-plugin-secrets-arrstack
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
