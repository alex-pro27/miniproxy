# miniproxy

Minimal HTTP proxy server on Go with YAML config and optional Basic auth.

## Run

```bash
go run . -config config.yaml
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

With auth:

```bash
curl -x http://user:secret@127.0.0.1:8080 http://example.com
```
