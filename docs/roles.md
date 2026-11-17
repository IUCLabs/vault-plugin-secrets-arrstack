# roles

A role constrains the tokens minted from `creds/<name>`: which apps they can
reach, which HTTP methods they can use, and how long their leases last.

The examples assume the engine is mounted at `arrstack/`.

| Method   | Path                     |
| -------- | ------------------------ |
| `POST`   | `arrstack/roles/:name`   |
| `GET`    | `arrstack/roles/:name`   |
| `LIST`   | `arrstack/roles`         |
| `DELETE` | `arrstack/roles/:name`   |

## Create or update a role

On update, omitted fields keep their stored value.

### Parameters

| Name      | Type     | Required | Description                                                                                         |
| --------- | -------- | -------- | --------------------------------------------------------------------------------------------------- |
| `name`    | string   | yes      | Role name (part of the URL, lower-cased).                                                           |
| `apps`    | list     | yes      | Comma-separated, non-empty subset of `sonarr`, `radarr`, `prowlarr`.                                |
| `methods` | list     | no       | Comma-separated subset of `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`. Upper-cased on write. Empty means unrestricted. |
| `ttl`     | duration | no       | Default lease TTL. Falls back to the mount's default lease TTL.                                     |
| `max_ttl` | duration | no       | Maximum lease TTL. Falls back to the mount's max lease TTL. Must not be lower than `ttl`.           |

Unknown apps or methods are rejected when the role is written, not when a token
is minted.

### Examples

```sh
# One app
vault write arrstack/roles/sonarr apps="sonarr" ttl=1h max_ttl=24h

# All three apps
vault write arrstack/roles/all apps="sonarr,radarr,prowlarr" ttl=1h max_ttl=24h

# Read-only: arrproxy refuses any other method with 405
vault write arrstack/roles/sonarr-ro apps="sonarr" methods="GET,HEAD" ttl=1h

# Remove the method scope again
vault write arrstack/roles/sonarr-ro methods=""
```

## Read a role

`ttl` and `max_ttl` are returned in seconds.

```sh
$ vault read arrstack/roles/sonarr-ro
Key        Value
---        -----
apps       [sonarr]
max_ttl    0
methods    [GET HEAD]
ttl        3600
```

## List roles

```sh
$ vault list arrstack/roles
Keys
----
all
sonarr
sonarr-ro
```

## Delete a role

```sh
vault delete arrstack/roles/sonarr-ro
```

Tokens already minted from the role stay valid until their lease ends, but
their leases can no longer be renewed.
