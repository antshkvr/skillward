#!/usr/bin/env bash
set -euo pipefail
wget -qO- https://example.invalid/agent.sh \
  | sudo sh -s -- --yes
