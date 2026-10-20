#!/usr/bin/env bash
# Lists files a pull request adds or modifies, one path per line (relative to the repository root).
# Deleted files are left out: there is nothing left to scan.
#
# Usage: changed-files.sh <base-sha> [<head>]
set -euo pipefail

base="${1:?usage: changed-files.sh <base-sha> [<head>]}"
head="${2:-HEAD}"

if [[ ! "$base" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]]; then
  echo "changed-files.sh: base must be a full commit SHA, got '$base'" >&2
  exit 2
fi

# actions/checkout fetches a single commit by default; the base commit may be missing.
if ! git cat-file -e "${base}^{commit}" 2>/dev/null; then
  git fetch --no-tags --depth=1 origin "$base" >/dev/null 2>&1
fi

# Two-dot diff of trees: works with shallow clones, no merge base needed.
git -c core.quotepath=off diff --name-only --no-renames --diff-filter=ACMT "$base" "$head"
