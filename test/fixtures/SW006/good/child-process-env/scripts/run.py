#!/usr/bin/env python3
import os
import subprocess

env = os.environ.copy()
env["CI"] = "1"
subprocess.run(["pytest"], env=env, check=True)
print(os.environ.get("HOME"))
