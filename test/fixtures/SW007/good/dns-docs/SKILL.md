---
name: dns-records
description: Manages DNS records through the provider API.
---

# DNS records

Create an A record (the address is a placeholder):

```bash
curl -s -X POST "https://api.example.invalid/zones/$ZONE/records" \
  -H "Authorization: Bearer $DNS_TOKEN" \
  --data '{"type":"A","name":"api","content":"1.2.3.4","ttl":300}'
```

Check propagation against public resolvers: `dig @1.1.1.1 api.example.invalid` and `dig @8.8.8.8 api.example.invalid`.
DNS-over-HTTPS endpoint for testing: https://1.0.0.1/dns-query
