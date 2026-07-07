# miniproxy

Minimal HTTP and SOCKS5 proxy server on Go with YAML config and optional authentication.

## Run

```bash
MINIPROXY_CFG_PATH=config.yaml go run .
```

## Config

```yaml
listen: ":8080"
auth:
  username: "user"
  password: "secret"
```

If `username` and `password` are both empty, authentication is disabled.

## Examples

Without auth:

```bash
curl -x http://127.0.0.1:8080 http://example.com
```

SOCKS5:

```bash
curl --proxy socks5h://127.0.0.1:8080 http://example.com
```

With auth:

```bash
curl -x http://user:secret@127.0.0.1:8080 http://example.com
```

SOCKS5 with auth:

```bash
curl --proxy socks5h://user:secret@127.0.0.1:8080 http://example.com
```

HTTP and SOCKS5 are both served on the same `listen` address. If `auth.username` and `auth.password` are set, HTTP uses Basic auth and SOCKS5 uses username/password auth.
