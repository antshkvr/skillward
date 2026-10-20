import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";

const ROOT = join(import.meta.dirname, "..");
const workflow = parse(readFileSync(join(ROOT, ".github/workflows/release.yml"), "utf8")) as {
  on: { push: { tags: string[]; branches?: string[] } };
  permissions: Record<string, string>;
  jobs: Record<string, { permissions: Record<string, string>; steps: Array<{ name?: string; uses?: string; run?: string }> }>;
};
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as { version: string };

describe("release workflow", () => {
  const steps = Object.values(workflow.jobs).flatMap((j) => j.steps);

  it("runs only for version tags and grants only what publishing needs", () => {
    expect(workflow.on.push).toEqual({ tags: ["v*"] });
    expect(workflow.permissions).toEqual({ contents: "read" });
    expect(workflow.jobs.publish!.permissions).toEqual({ contents: "read", "id-token": "write" });
  });

  it("uses trusted publishing, not a stored token", () => {
    const text = readFileSync(join(ROOT, ".github/workflows/release.yml"), "utf8");
    expect(text).not.toMatch(/secrets\.|NODE_AUTH_TOKEN|NPM_TOKEN/);
    expect(steps.some((s) => s.run?.includes("npm publish --provenance"))).toBe(true);
  });

  it("pins actions to full commit SHAs and keeps expressions out of shell scripts", () => {
    for (const s of steps) {
      if (s.uses) expect(s.uses).toMatch(/^[\w.-]+\/[\w./-]+@[0-9a-f]{40}$/);
      if (s.run) expect(s.run, s.name).not.toContain("${{");
    }
  });
});

describe("scripts/check-release.mjs", () => {
  const check = (tag: string) => spawnSync(process.execPath, [join(ROOT, "scripts/check-release.mjs"), tag], { cwd: ROOT, encoding: "utf8" });

  it("accepts the tag of the current version", () => {
    const r = check(`v${pkg.version}`);
    expect(r.status, r.stderr).toBe(0);
  });

  it("rejects a tag that doesn't match package.json", () => {
    const r = check("v9.9.9");
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("does not match package.json");
  });
});
