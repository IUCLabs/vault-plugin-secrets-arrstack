# config

The `config` path holds the connection to arrproxy's admin API. The engine
uses it to mint (`POST /api/admin/tokens`) and revoke
(`DELETE /api/admin/tokens/{id}`) tokens. The stored config is seal-wrapped.

The examples assume the engine is mounted at `arrstack/`.

| Method   | Path              |
| -------- | ----------------- |
| `POST`   | `arrstack/config` |
| `GET`    | `arrstack/config` |
| `DELETE` | `arrstack/config` |

## Write config

Creates or updates the config. On update, omitted fields keep their stored
value.

### Parameters

| Name                      | Type   | Required | Default | Description                                                                 |
| ------------------------- | ------ | -------- | ------- | --------------------------------------------------------------------------- |
| `base_url`                | string | on first write |         | Base URL of the arrproxy deployment, e.g. `https://arrproxy.example.com`.   |
| `admin_token`             | string | on first write |         | arrproxy admin bearer token. Write-only: never returned on read.            |
| `ca_cert`                 | string | no       | `""`    | PEM CA certificate used to verify arrproxy's TLS certificate. Empty uses the system trust store. |
| `request_timeout_seconds` | int    | no       | `30`    | HTTP timeout, in seconds, for admin API calls.                              |

### Example

```sh
vault write arrstack/config \
  base_url=https://arrproxy.example.com \
  admin_token="$ARRPROXY_ADMIN_TOKEN" \
  ca_cert=@ca.pem \
  request_timeout_seconds=15
```

## Read config

Returns everything except `admin_token`.

```sh
$ vault read arrstack/config
Key                        Value
---                        -----
base_url                   https://arrproxy.example.com
ca_cert                    -----BEGIN CERTIFICATE-----...
request_timeout_seconds    15
```

## Delete config

```sh
vault delete arrstack/config
```

Existing leases cannot be revoked in arrproxy until a config is written again.
