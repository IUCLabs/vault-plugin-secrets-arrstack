# creds

Reading `creds/<name>` mints a new arrproxy machine token for the named role
and wraps it in a lease.

The examples assume the engine is mounted at `arrstack/`.

| Method        | Path                   |
| ------------- | ---------------------- |
| `GET` / `POST` | `arrstack/creds/:name` |

## Mint a token

### Parameters

| Name   | Type   | Required | Description                      |
| ------ | ------ | -------- | -------------------------------- |
| `name` | string | yes      | Role to mint for (part of the URL). |

### Example

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

### Response fields

| Field        | Description                                                           |
| ------------ | --------------------------------------------------------------------- |
| `token`      | The arrproxy machine token. Send it to arrproxy as a bearer token.    |
| `id`         | arrproxy's token id, used for revocation.                             |
| `apps`       | Apps the token can reach (from the role).                             |
| `methods`    | HTTP methods the token is limited to; empty means unrestricted.       |
| `subject`    | `vault:arrstack:<role>`. arrproxy requires the `vault:arrstack:` prefix. |
| `expires_at` | The token's fixed expiry in arrproxy (RFC 3339).                      |

## Renewal

The token's expiry is fixed in arrproxy when it is minted (the lease TTL is
sent as `ttl_seconds`), and arrproxy does not extend issued tokens. Renewing
the lease therefore never goes past `expires_at`: the new TTL is capped at the
time remaining, and an expired token is not renewed. Mint a new token, or raise
the role's `ttl`, for longer-lived access.

```sh
vault lease renew arrstack/creds/media/AbC...
```

## Revocation

Revoking the lease disables the token in arrproxy
(`DELETE /api/admin/tokens/{id}`):

```sh
vault lease revoke arrstack/creds/media/AbC...

# every token minted from one role
vault lease revoke -prefix arrstack/creds/media
```
