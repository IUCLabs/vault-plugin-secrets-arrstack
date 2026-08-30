# vault-plugin-secrets-arrstack

A dynamic secrets engine that mints **arrproxy machine tokens** on both
**HashiCorp Vault** and **[OpenBao](https://openbao.org)**.

[arrproxy](https://git.unkin.net/unkin/arrproxy) fronts the *arr apps
(Sonarr / Radarr / Prowlarr) behind a single OAuth-gated proxy that brokers
per-caller API tokens. Its human path derives scope from OAuth identity headers,
so a non-interactive caller cannot use it. This engine calls arrproxy's
bearer-gated **admin API** (`/api/admin/tokens`) instead, so Terraform-driven
*arr onboarding can mint and revoke machine tokens without a human in the loop.

Each minted token is:

- **scoped to a subset of apps** (`apps`: any of `sonarr`, `radarr`, `prowlarr`)
- **optionally scoped to HTTP methods** (`methods`, e.g. `GET,HEAD` for a
  read-only consumer; empty means unrestricted)
- **subject-namespaced** as `vault:arrstack:<role>` (arrproxy requires the prefix)
- **bound to a Vault lease** — revoking the lease disables the token in arrproxy

## Vault and OpenBao

OpenBao is a fork of Vault and keeps its plugin protocol compatible, so the
**same plugin binary** registers and runs on either engine unchanged — the CLI
commands below are identical apart from `vault` vs `bao`.

## How it works

The backend authenticates to arrproxy's admin API with the admin bearer token
and manages tokens through `POST /api/admin/tokens` (mint) and
`DELETE /api/admin/tokens/{id}` (revoke). Each minted token is wrapped in a
Vault lease, so Vault owns the token's lifecycle: revoke disables it, renew
extends it up to the token's fixed expiry.

```
┌────────┐  read creds/<role>  ┌────────────────────────┐  POST /api/admin/tokens  ┌──────────┐
│ client │ ──────────────────► │ vault + arrstack plugin │ ───────────────────────► │ arrproxy │
└────────┘  ◄── machine token ─└────────────────────────┘  ◄──── {id, token} ────── └──────────┘
```

## Usage

```sh
# 1. Enable the engine
vault secrets enable -path=arrstack vault-plugin-secrets-arrstack

# 2. Configure the connection to arrproxy's admin API
vault write arrstack/config \
  base_url=https://arrstack.unkin.net \
  admin_token=$ARRPROXY_ADMIN_TOKEN \
  ca_cert=@traefik-external-ca.pem   # optional

# 3. Define a role: which apps, what TTLs
#    (add methods="GET,HEAD" to pin the token to those HTTP methods)
vault write arrstack/roles/media \
  apps="sonarr,radarr" \
  ttl=1h \
  max_ttl=24h

# 4. Mint a scoped, time-limited machine token
vault read arrstack/creds/media
# Key           Value
# ---           -----
# lease_id      arrstack/creds/media/AbC...
# lease_duration 1h
# apps          [radarr sonarr]
# methods       []
# id            tok-...
# subject       vault:arrstack:media
# token         arr_...

# 5. Revoking the lease disables the token in arrproxy
vault lease revoke arrstack/creds/media/AbC...
```

### Example roles

| Role       | `apps`                        | Use                                  |
| ---------- | ----------------------------- | ------------------------------------ |
| `sonarr`   | `sonarr`                      | a token that only reaches Sonarr     |
| `radarr`   | `radarr`                      | a token that only reaches Radarr     |
| `prowlarr` | `prowlarr`                    | a token that only reaches Prowlarr   |
| `all`      | `sonarr,radarr,prowlarr`      | a token that reaches all three apps  |

```sh
vault write arrstack/roles/sonarr   apps="sonarr"                   ttl=1h max_ttl=24h
vault write arrstack/roles/radarr   apps="radarr"                   ttl=1h max_ttl=24h
vault write arrstack/roles/prowlarr apps="prowlarr"                 ttl=1h max_ttl=24h
vault write arrstack/roles/all      apps="sonarr,radarr,prowlarr"   ttl=1h max_ttl=24h
```

## Paths

| Path             | Ops                | Description                                       |
| ---------------- | ------------------ | ------------------------------------------------- |
| `config`         | read/write/delete  | arrproxy connection (`base_url`, `admin_token`)   |
| `roles/<name>`   | read/write/delete  | Constraints for minted tokens                     |
| `roles/`         | list               | List configured roles                             |
| `creds/<name>`   | read               | Mint a machine token for the role                 |

### Config fields

| Field                     | Type     | Description                                                          |
| ------------------------- | -------- | ------------------------------------------------------------------- |
| `base_url`                | string   | arrproxy base URL, e.g. `https://arrstack.unkin.net`                |
| `admin_token`             | string   | arrproxy admin bearer token (write-only, never returned on read)    |
| `ca_cert`                 | string   | PEM CA to verify the arrproxy TLS cert; empty uses the system store |
| `request_timeout_seconds` | int      | HTTP timeout for admin API calls (default 30)                       |

### Role fields

| Field     | Type     | Description                                                         |
| --------- | -------- | ------------------------------------------------------------------ |
| `apps`    | list     | Non-empty subset of `sonarr`/`radarr`/`prowlarr`                   |
| `methods` | list     | Optional HTTP methods the token is limited to; empty = unrestricted |
| `ttl`     | duration | Default lease TTL                                                   |
| `max_ttl` | duration | Maximum lease TTL                                                   |

## Method scoping

A role may pin its tokens to a set of HTTP methods, so a read-only integration
cannot write to the *arr even on an app it is allowed to reach. Entries are
uppercase-normalized and must name one of `GET`, `HEAD`, `POST`, `PUT`,
`PATCH`, `DELETE`, `OPTIONS` — an unknown method is rejected at role write, not
at mint. The scope is sent to arrproxy at mint time and enforced there: a
request outside it is refused with `405` before any upstream *arr is reached.

Leaving `methods` unset (the default) leaves the token unrestricted, exactly as
before this field existed.

```sh
# A token that can read Sonarr but never change it.
vault write arrstack/roles/sonarr-ro apps="sonarr" methods="GET,HEAD" ttl=1h max_ttl=24h

# Drop the scope again on an existing role.
vault write arrstack/roles/sonarr-ro methods=""
```

## TTL and renewal

At mint time the effective initial lease TTL is sent to arrproxy as
`ttl_seconds`, so the arrproxy token is given a **fixed expiry** at that point
(`expires_at` in the mint response, which the engine stores). Because that
expiry is fixed and arrproxy does not extend an already-issued token, a lease
renewal can never push the lease past the token's expiry: the renew callback
honours the role's `max_ttl` but **caps the renewed TTL at the remaining time to
the token's expiry**, and an already-expired token is not extended. For a
longer-lived token, issue a new one (or set a larger role `ttl`).

## Development

```sh
make build   # build the plugin into ./dist
make test    # unit tests (race-enabled)
make lint    # go vet
make fmt     # gofmt
make rpm     # build the binary and package the Vault + OpenBao RPMs
```

### Releasing

Versioning is tag-driven; pushing a `v*` tag runs the release pipeline, which
builds the binary, packages the Vault (`/opt/vault-plugins`) and OpenBao
(`/opt/openbao-plugins`) RPMs, prints the binary `sha256` for Puppet plugin
registration, and uploads the RPMs to the artifactapi `rpm-internal` repo.

```sh
make patch   # v0.1.0 -> v0.1.1
make minor   # v0.1.1 -> v0.2.0
make major   # v0.2.0 -> v1.0.0
```
