import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { expect, it } from "vitest";

/**
 * The scanner's own code must not contain raw invisible characters: write them as `\uXXXX` escapes.
 * Fixtures are exempt — some contain invisible Unicode on purpose.
 */
const RAW_INVISIBLE =
  /[\p{Cf}\p{Zl}\p{Zp}\u00A0\u1680\u2000-\u200A\u202F\u205F\u3000\u034F\u115F\u1160\u17B4\u17B5\u180B-\u180F\u3164\uFE00-\uFE0F\uFFA0\uFFF0-\uFFFB\u{E0100}-\u{E01EF}]|[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/u;

const ROOT = join(import.meta.dirname, "..");

function sources(dir: string, all = false): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    if ((!all && name === "fixtures") || name === "node_modules") return [];
    return statSync(p).isDirectory() ? sources(p, all) : all || /\.(ts|js|mjs|json|md)$/.test(name) ? [p] : [];
  });
}

it("source files contain no raw invisible characters", () => {
  const files = ["src", "test", "scripts"].flatMap((dir) => sources(join(ROOT, dir)));
  const offenders = files.flatMap((file) =>
    readFileSync(file, "utf8")
      .split("\n")
      .flatMap((line, i) => (RAW_INVISIBLE.test(line) ? [`${relative(ROOT, file)}:${i + 1}`] : [])),
  );
  expect(offenders).toEqual([]);
});

it("rules use execAll instead of String.prototype.matchAll on regex constants", () => {
  // matchAll clones the regex per call; on per-line loops that made scans ~5x slower.
  const offenders = sources(join(ROOT, "src", "rules")).flatMap((file) =>
    readFileSync(file, "utf8")
      .split("\n")
      .flatMap((line, i) => (/\.matchAll\(\s*[A-Za-z_]/.test(line) ? [`${relative(ROOT, file)}:${i + 1}`] : [])),
  );
  expect(offenders).toEqual([]);
});

it("keeps antivirus-sensitive command vocabulary out of shipped code (it lives in src/rules/data)", () => {
  // ML-based antivirus quarantined dist/rules/SW004-pipe-to-shell.js for containing PowerShell
  // download-and-execute vocabulary inside detection regexes. Rules use vocab() from src/rules/vocabulary.ts.
  const SENSITIVE = /invoke-expression|downloadstring|webclient|invoke-webrequest|invoke-restmethod|frombase64string|tcpclient|bitstransfer|\b(?:iex|iwr|irm)\b/i;
  const offenders = sources(join(ROOT, "src"))
    .filter((file) => file.endsWith(".ts"))
    .flatMap((file) =>
      readFileSync(file, "utf8")
        .split("\n")
        .flatMap((line, i) => (SENSITIVE.test(line) ? [`${relative(ROOT, file)}:${i + 1}`] : [])),
    );
  expect(offenders).toEqual([]);
});

it("doesn't let git ignore any fixture (a fixture missing from a commit only fails in CI)", () => {
  // Personal global ignores often cover `.claude/settings.local.json` or `.env`; such fixtures need `git add -f`.
  const files = sources(join(ROOT, "test", "fixtures"), true).map((f) => relative(ROOT, f).split("\\").join("/"));
  const r = spawnSync("git", ["check-ignore", "--stdin"], { cwd: ROOT, input: files.join("\n"), encoding: "utf8" });
  if (r.error) return; // git not available
  const ignored = r.stdout.split("\n").filter(Boolean);
  expect(ignored, "ignored fixtures — add them with `git add -f`").toEqual([]);
});
