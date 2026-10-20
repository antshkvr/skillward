# Security policy

skillward reads untrusted files by design, so bugs in the scanner itself matter. Thank you for reporting them.

## Reporting a vulnerability

Please report privately through GitHub: **Security → Report a vulnerability** on
[github.com/antshkvr/skillward](https://github.com/antshkvr/skillward/security/advisories/new). Don't open a public issue
for anything that could be exploited.

Include the version (`skillward --version`), the command you ran, and a minimal file that reproduces the problem. Use
inert stand-ins for anything dangerous (`example.invalid`, `203.0.113.x`, `FAKE_KEY_…`), never live payloads or real
credentials.

You'll get an acknowledgement within 3 working days and a fix or a plan within 30 days. We credit reporters in the
release notes unless you'd rather not be named.

## In scope

- The scanner executing, importing or fetching anything from scanned files, or making any network request.
- Reading or writing outside the scanned folder: path traversal through the lockfile, snapshots, symlinks or hook
  targets.
- Output injection: terminal escape sequences, bidi controls or markup from scanned files reaching the text, JSON,
  SARIF or job-summary output unescaped.
- A crafted file that makes a scan hang or take excessive time or memory (regex blow-ups, huge inputs).
- Secrets printed in full in findings or snippets.
- The GitHub Action: script injection through inputs or scanned content, token exposure.

## Not a vulnerability

A dangerous pattern that skillward doesn't detect (a false negative), or a safe one it flags (a false positive), is a
rule-quality issue — please open a regular issue with an inert example. Static analysis can't catch everything, and
skillward is one layer, not a guarantee.

## Supported versions

Only the latest release gets fixes.
