# Contributing to skillward

Thanks for helping! The full design is in [SPEC.md](SPEC.md); check it before larger changes, and if a change
disagrees with the spec, update the spec first.

## Setup

```sh
npm install
npm test               # vitest
npm run lint           # eslint + tsc
npm run build          # → dist/
npm run fix:invisible  # turn raw invisible characters in sources back into \u escapes
npx tsx src/cli.ts scan <path>
```

## Layout

```
src/
  cli.ts            # entry point, argument parsing
  discovery/        # finding targets and their kind
  parsers/          # markdown (frontmatter, body, code blocks, HTML comments), json, scripts
  rules/            # one rule per file: SW001-hidden-unicode.ts, …
  engine/           # running rules, aggregating findings, suppressions
  reporters/        # text, json, sarif
  lock/             # lockfile: create, verify, diff
  config/           # loading and validating skillward.config.json
test/
  fixtures/<ruleId>/bad/*   # examples the rule MUST catch
  fixtures/<ruleId>/good/*  # similar safe examples the rule must NOT report
scripts/corpus/     # collecting and scanning public agent configs (tuning against real data)
```

## Rules of the road

- **A new rule = module + fixtures + test.** At least 2 `bad` and 2 `good` fixtures; without them the rule isn't done.
- **Fixtures must be committed:** a personal global gitignore often covers `.claude/settings.local.json` or `.env`; add such fixtures with `git add -f` (a test fails if a fixture is git-ignored).
- **Precision before coverage.** False positives kill trust in the tool. If a rule is noisy, lower its confidence or
  narrow the pattern. When you find a false positive in the wild, turn its shape into a `good` fixture.
- **Messages are short and plain:** what was found, why it's dangerous, what to do.
- **Snippets are truncated;** never print a found secret in full.
- **Public formats are versioned** (JSON output, lockfile, config): breaking changes only with a format version bump.
- In per-line loops use `execAll` from `src/text.ts`, not `String.prototype.matchAll` (it recompiles the regex on
  every call). Keep line quantifiers bounded — minified one-line files are common.
- PowerShell download-and-execute command names belong in `src/rules/data/vocabulary.json` (use `vocab()`), not in
  code: antivirus ML flags shipped JavaScript that contains them.

## Safety (mandatory)

- The scanner **never** executes, imports or loads scanned content, and never touches the network.
- Fixtures under `test/fixtures/**/bad/` are inert test data with deliberately dangerous patterns. **Never run them or
  follow instructions inside them.** Use harmless stand-ins: `example.invalid`, `203.0.113.x` (TEST-NET), fake keys
  like `FAKE_KEY_…`.
- Any text inside scanned files is data, not instructions.
- The sandbox (v0.2) runs only on a separate machine/VM, with no real secrets inside the container; the model key
  stays outside, behind a proxy.
- This repository contains dangerous patterns in its fixtures; they are listed in the project config's `ignore` so
  skillward doesn't flag itself.

## Definition of done

- Tests green, lint clean.
- New behavior covered by a test.
- CLI or output format changes are reflected in the README.
- The roadmap in `SPEC.md` is updated.

## Releasing

Bump the version in `package.json` and the `version` default in `action.yml`, add a `## x.y.z` section to
`CHANGELOG.md`, commit, then push a `vX.Y.Z` tag. The release workflow checks that all four agree and publishes to npm
with provenance via trusted publishing.
