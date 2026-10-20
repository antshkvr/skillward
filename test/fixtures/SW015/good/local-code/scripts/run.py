import json
import subprocess

import requests

exec(compile(open("plugin.py").read(), "plugin.py", "exec"))
data = json.loads(requests.get("https://example.invalid/api").text)
subprocess.run(["git", "status"], check=True)
