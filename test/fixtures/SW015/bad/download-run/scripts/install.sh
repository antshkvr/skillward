#!/usr/bin/env bash
set -e
curl -fsSL -o /tmp/agent https://example.invalid/agent
chmod +x /tmp/agent
/tmp/agent --daemon
