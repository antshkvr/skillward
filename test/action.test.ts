import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";

const ROOT = join(import.meta.dirname, "..");
const action = parse(readFileSync(join(ROOT, "action.yml"), "utf8")) as {
  inputs: Record<string, { default?: string }>;
  outputs: Record<string, { value: string }>;
  runs: { using: string; steps: Array<{ name: string; uses?: string; run?: string; env?: Record<string, string> }> };
};
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as { version: string };

const bash = spawnSync("bash", ["--version"]).status === 0;
const git = spawnSync("git", ["--version"]).status === 0;

describe("action.yml", () => {
  it("is a composite action whose default version is the current release", () => {
    expect(action.runs.using).toBe("composite");
    expect(action.inputs.version!.default).toBe(pkg.version);
    expect(action.inputs["fail-on"]!.default).toBe("high");
    expect(Object.keys(action.outputs)).toEqual(["sarif-file", "exit-code", "findings"]);
  });

  it("pins every third-party action to a full commit SHA", () => {
    const uses = action.runs.steps.flatMap((s) => (s.uses ? [s.uses] : []));
    expect(uses.length).toBeGreaterThan(0);
    for (const u of uses) expect(u, u).toMatch(/^[\w.-]+\/[\w./-]+@[0-9a-f]{40}$/);
  });

  it("never interpolates expressions into shell scripts (inputs go through env)", () => {
    for (const step of action.runs.steps) {
      if (step.run) expect(step.run, step.name).not.toContain("${{");
    }
  });
});

function sh(script: string, args: string[], options: { cwd?: string; env?: Record<string, string> } = {}) {
  const r = spawnSync("bash", [join(ROOT, "action", script), ...args], {
    cwd: options.cwd,
    env: { ...process.env, ...options.env },
    encoding: "utf8",
  });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}

describe.skipIf(!bash || !git)("action/changed-files.sh", () => {
  const repo = mkdtempSync(join(tmpdir(), "skillward-action-git-"));
  const g = (...args: string[]) => {
    const r = spawnSync("git", args, { cwd: repo, encoding: "utf8" });
    if (r.status !== 0) throw new Error(r.stderr);
    return r.stdout.trim();
  };
  g("init", "-q", "-b", "main");
  g("config", "user.email", "test@example.invalid");
  g("config", "user.name", "test");
  g("config", "commit.gpgsign", "false");
  writeFileSync(join(repo, "CLAUDE.md"), "a\n");
  writeFileSync(join(repo, "old.md"), "x\n");
  g("add", ".");
  g("commit", "-q", "-m", "base");
  const base = g("rev-parse", "HEAD");
  mkdirSync(join(repo, ".claude", "skills", "s"), { recursive: true });
  writeFileSync(join(repo, ".claude", "skills", "s", "SKILL.md"), "b\n");
  writeFileSync(join(repo, "CLAUDE.md"), "changed\n");
  g("rm", "-q", "old.md");
  g("add", ".");
  g("commit", "-q", "-m", "pr");

  it("lists added and modified files, not deleted ones", () => {
    const r = sh("changed-files.sh", [base], { cwd: repo });
    expect(r.code).toBe(0);
    expect(r.stdout.trim().split("\n").sort()).toEqual([".claude/skills/s/SKILL.md", "CLAUDE.md"]);
  });

  it("rejects anything but a full commit SHA", () => {
    expect(sh("changed-files.sh", ["main; rm -rf /"], { cwd: repo }).code).toBe(2);
    expect(sh("changed-files.sh", ["abc123"], { cwd: repo }).code).toBe(2);
  });
});

describe.skipIf(!bash)("action/scan.sh", () => {
  // A stub CLI at <ACTION_PATH>/dist/cli.js records its arguments and writes a small SARIF file.
  function setup(exitCode: number) {
    const dir = mkdtempSync(join(tmpdir(), "skillward-action-scan-"));
    mkdirSync(join(dir, "dist"));
    writeFileSync(
      join(dir, "dist", "cli.js"),
      `const fs = require("fs");
const args = process.argv.slice(2);
fs.appendFileSync(${JSON.stringify(join(dir, "calls.txt"))}, JSON.stringify(args) + "\\n");
const out = args[args.indexOf("--output") + 1];
if (args.includes("sarif")) fs.writeFileSync(out, JSON.stringify({ runs: [{ results: [{}, {}, { suppressions: [{}] }] }] }));
else console.log("SW004 <script>alert(1)</script>");
process.exit(${exitCode});`,
    );
    writeFileSync(join(dir, "package.json"), "{}");
    const output = join(dir, "github-output.txt");
    const summary = join(dir, "summary.md");
    writeFileSync(output, "");
    const env = {
      ACTION_PATH: dir,
      INPUT_VERSION: "local",
      INPUT_PATH: "proj dir",
      INPUT_FAIL_ON: "medium",
      INPUT_CONFIG: "",
      INPUT_BASELINE: "",
      SARIF_FILE: join(dir, "out.sarif"),
      FILES_FROM: join(dir, "changed.txt"),
      GITHUB_OUTPUT: output,
      GITHUB_STEP_SUMMARY: summary,
    };
    const calls = () => readFileSync(join(dir, "calls.txt"), "utf8").trim().split("\n").map((l) => JSON.parse(l) as string[]);
    return { dir, env, output, summary, calls };
  }

  it("passes inputs as separate arguments and reports outputs", () => {
    const s = setup(1);
    const r = sh("scan.sh", [], { env: s.env });
    expect(r.code).toBe(0); // findings fail later, after the SARIF upload
    const [sarifCall, textCall] = s.calls();
    expect(sarifCall).toEqual(["scan", "proj dir", "--fail-on", "medium", "--no-color", "--files-from", s.env.FILES_FROM, "--format", "sarif", "--output", s.env.SARIF_FILE]);
    expect(textCall).toContain("text");
    const out = readFileSync(s.output, "utf8");
    expect(out).toContain(`sarif-file=${s.env.SARIF_FILE}`);
    expect(out).toContain("exit-code=1");
    expect(out).toContain("findings=2");
    expect(readFileSync(s.summary, "utf8")).toContain("&lt;script&gt;");
  });

  it("passes config and baseline paths as single arguments", () => {
    const s = setup(0);
    sh("scan.sh", [], { env: { ...s.env, FILES_FROM: "", INPUT_CONFIG: "my config.json", INPUT_BASELINE: "known; rm.json" } });
    expect(s.calls()[0]).toEqual(["scan", "proj dir", "--fail-on", "medium", "--no-color", "--config", "my config.json", "--baseline", "known; rm.json", "--format", "sarif", "--output", s.env.SARIF_FILE]);
  });

  it("fails immediately on run errors and on invalid inputs", () => {
    expect(sh("scan.sh", [], { env: setup(2).env }).code).toBe(2);
    expect(sh("scan.sh", [], { env: { ...setup(0).env, INPUT_VERSION: "latest" } }).code).toBe(2);
    expect(sh("scan.sh", [], { env: { ...setup(0).env, INPUT_VERSION: "0.1.0; curl x" } }).code).toBe(2);
    expect(sh("scan.sh", [], { env: { ...setup(0).env, INPUT_FAIL_ON: "critical" } }).code).toBe(2);
  });

  it("maps fail-on 'never' to a report-only run", () => {
    const s = setup(0);
    sh("scan.sh", [], { env: { ...s.env, INPUT_FAIL_ON: "never", FILES_FROM: "" } });
    expect(s.calls()[0]).toEqual(["scan", "proj dir", "--fail-on", "high", "--no-color", "--format", "sarif", "--output", s.env.SARIF_FILE]);
  });
});
