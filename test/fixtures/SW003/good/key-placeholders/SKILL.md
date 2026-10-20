---
name: tls-secret
description: Creates a Kubernetes TLS secret from your own certificate and key.
---

# TLS secret

Put your own key into the manifest (never commit it):

```yaml
stringData:
  tls.key: |
    -----BEGIN PRIVATE KEY-----
    ...
    -----END PRIVATE KEY-----
```

| Secret type | Looks like |
|---|---|
| Private key file | `-----BEGIN RSA PRIVATE KEY-----` |
| JWT | the jwt.io sample `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.FAKEsignatureFAKEsignatureFAKE` |
