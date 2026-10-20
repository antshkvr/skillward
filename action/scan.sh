#!/usr/bin/env bash
# Runs skillward for the GitHub Action. All inputs arrive as environment variables (never
# interpolated into the script), so a crafted input can't inject shell code.
#
#   INPUT_PATH, INPUT_VERSION, INPUT_FAIL_ON, INPUT_CONFIG, SARIF_FILE, FILES_FROM, ACTION_PATH
#   GITHUB_OUTPUT, GITHUB_STEP_SUMMARY (set by the runner)
set -uo pipefail

INPUT_PATH="${INPUT_PATH:-.}"
INPUT_FAIL_ON="${INPUT_FAIL_ON:-high}"
INPUT_CONFIG="${INPUT_CONFIG:-}"
SARIF_FILE="${SARIF_FILE:-skillward.sarif}"
FILES_FROM="${FILES_FROM:-}"
GITHUB_OUTPUT="${GITHUB_OUTPUT:-/dev/null}"
GITHUB_STEP_SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/null}"

if [ "${INPUT_VERSION:-}" = "local" ]; then
  cli=(node "$ACTION_PATH/dist/cli.js")
elif [[ "${INPUT_VERSION:-}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  # An exact version only: a scanner that preaches pinning shouldn't run "latest" itself.
  cli=(npx --yes "skillward@$INPUT_VERSION")
else
  echo "::error::skillward: 'version' must be an exact version like 0.1.0, or 'local'"
  exit 2
fi

case "$INPUT_FAIL_ON" in
  info | low | medium | high) fail_on="$INPUT_FAIL_ON" ;;
  never) fail_on="high" ;;
  *)
    echo "::error::skillward: 'fail-on' must be info, low, medium, high or never"
    exit 2
    ;;
esac

args=(scan "$INPUT_PATH" --fail-on "$fail_on" --no-color)
[ -n "$INPUT_CONFIG" ] && args+=(--config "$INPUT_CONFIG")
[ -n "$FILES_FROM" ] && args+=(--files-from "$FILES_FROM")

"${cli[@]}" "${args[@]}" --format sarif --output "$SARIF_FILE"
code=$?

# Human-readable report in the job summary, HTML-escaped (it quotes scanned content).
{
  echo "### skillward"
  echo
  echo "<pre>"
  "${cli[@]}" "${args[@]}" --format text 2>&1 | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
  echo "</pre>"
} >>"$GITHUB_STEP_SUMMARY"

findings=0
if [ -f "$SARIF_FILE" ]; then
  # Active (not inline-suppressed) results.
  findings=$(node -e 'const r = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")); console.log(r.runs[0].results.filter((x) => !x.suppressions).length)' "$SARIF_FILE")
  echo "sarif-file=$SARIF_FILE" >>"$GITHUB_OUTPUT"
fi
echo "exit-code=$code" >>"$GITHUB_OUTPUT"
echo "findings=$findings" >>"$GITHUB_OUTPUT"

# Run errors fail right away; findings fail in a later step, after the SARIF upload.
if [ "$code" -ge 2 ]; then
  echo "::error::skillward failed to run (exit code $code)"
  exit "$code"
fi
exit 0
