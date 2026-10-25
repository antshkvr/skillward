import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { classifyFile, discover, DiscoveryError } from "../src/discovery/index.js";

/** Builds a throwaway directory tree. Discovery trees live in tmp, not in fixtures, because their .gitignore files would affect this repo. */
function tree(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), "skillward-disc-"));
  for (const [rel, content] of Object.entries(files)) {
    const p = join(root, rel);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, content);
  }
  return root;
}

const summary = (targets: Array<{ kind: string; path: string; files: Array<{ path: string }> }>) =>
  targets.map((t) => ({ kind: t.kind, path: t.path, files: t.files.map((f) => f.path) }));

describe("discovery", () => {
  const project = tree({
    "CLAUDE.md": "# root",
    "CLAUDE.local.md": "# local, gitignored",
    "README.md": "# not a target",
    "docs/AGENTS.md": "# nested",
    ".gitignore": "build/\nCLAUDE.local.md\n.claude/settings.local.json\n*.log\n",
    "build/CLAUDE.md": "# ignored by .gitignore",
    "node_modules/pkg/CLAUDE.md": "# never scanned",
    "vendor/CLAUDE.md": "# ignored by config",
    ".mcp.json": "{}",
    ".claude/settings.json": "{}",
    ".claude/settings.local.json": "{}",
    ".claude/commands/deploy.md": "# command",
    ".claude/agents/reviewer.md": "# agent",
    ".claude/skills/pdf/SKILL.md": "---\nname: pdf\n---\n",
    ".claude/skills/pdf/scripts/run.py": "print(1)",
    ".claude/skills/pdf/debug.log": "gitignored but inside .claude",
    ".claude/skills/pdf/inner/SKILL.md": "---\nname: inner\n---\n",
    ".claude/skills/pdf/inner/notes.md": "inner notes",
    "plugin/.claude-plugin/plugin.json": "{}",
    "plugin/.claude-plugin/marketplace.json": "{}",
    "plugin/commands/hello.md": "# hello",
    "plugin/agents/helper.md": "# helper",
    "plugin/hooks/hooks.json": "{}",
    "plugin/skills/x/SKILL.md": "---\nname: x\n---\n",
    "plugin/README.md": "# not a target",
    "other/commands/not-a-plugin.md": "# not a target",
    "src/settings.json": "{}",
  });

  it("finds and classifies every target type", async () => {
    const result = await discover({ path: project, ignore: ["vendor/"] });
    expect(summary(result.targets)).toEqual([
      { kind: "instructions", path: ".claude/agents/reviewer.md", files: [".claude/agents/reviewer.md"] },
      { kind: "instructions", path: ".claude/commands/deploy.md", files: [".claude/commands/deploy.md"] },
      { kind: "settings", path: ".claude/settings.json", files: [".claude/settings.json"] },
      { kind: "settings", path: ".claude/settings.local.json", files: [".claude/settings.local.json"] },
      {
        kind: "skill",
        path: ".claude/skills/pdf",
        files: [".claude/skills/pdf/SKILL.md", ".claude/skills/pdf/debug.log", ".claude/skills/pdf/scripts/run.py"],
      },
      {
        kind: "skill",
        path: ".claude/skills/pdf/inner",
        files: [".claude/skills/pdf/inner/SKILL.md", ".claude/skills/pdf/inner/notes.md"],
      },
      { kind: "mcp-config", path: ".mcp.json", files: [".mcp.json"] },
      { kind: "instructions", path: "CLAUDE.local.md", files: ["CLAUDE.local.md"] },
      { kind: "instructions", path: "CLAUDE.md", files: ["CLAUDE.md"] },
      { kind: "instructions", path: "docs/AGENTS.md", files: ["docs/AGENTS.md"] },
      { kind: "plugin-manifest", path: "plugin/.claude-plugin/marketplace.json", files: ["plugin/.claude-plugin/marketplace.json"] },
      { kind: "plugin-manifest", path: "plugin/.claude-plugin/plugin.json", files: ["plugin/.claude-plugin/plugin.json"] },
      { kind: "instructions", path: "plugin/agents/helper.md", files: ["plugin/agents/helper.md"] },
      { kind: "instructions", path: "plugin/commands/hello.md", files: ["plugin/commands/hello.md"] },
      { kind: "settings", path: "plugin/hooks/hooks.json", files: ["plugin/hooks/hooks.json"] },
      { kind: "skill", path: "plugin/skills/x", files: ["plugin/skills/x/SKILL.md"] },
    ]);
  });

  it("respects .gitignore and config ignore, and never enters node_modules", async () => {
    const result = await discover({ path: project, ignore: ["vendor/"] });
    const paths = result.targets.flatMap((t) => t.files.map((f) => f.path));
    expect(paths).not.toContain("build/CLAUDE.md");
    expect(paths).not.toContain("vendor/CLAUDE.md");
    expect(paths).not.toContain("node_modules/pkg/CLAUDE.md");
    // Without the config ignore, vendor/ is scanned.
    const all = await discover({ path: project });
    expect(all.targets.map((t) => t.path)).toContain("vendor/CLAUDE.md");
  });

  it("applies nested .gitignore files relative to their directory", async () => {
    const root = tree({
      "pkg/.gitignore": "generated/\n",
      "pkg/generated/CLAUDE.md": "x",
      "pkg/CLAUDE.md": "x",
      "generated/CLAUDE.md": "x",
    });
    const result = await discover({ path: root });
    expect(result.targets.map((t) => t.path)).toEqual(["generated/CLAUDE.md", "pkg/CLAUDE.md"]);
  });

  it("scans a single file, treating unknown names as instructions", async () => {
    const one = await discover({ path: join(project, "README.md") });
    expect(summary(one.targets)).toEqual([{ kind: "instructions", path: "README.md", files: ["README.md"] }]);
    const settings = await discover({ path: join(project, ".claude", "settings.json") });
    expect(settings.targets[0]!.kind).toBe("settings");
  });

  it("scans the whole skill when given its SKILL.md", async () => {
    const result = await discover({ path: join(project, "plugin", "skills", "x", "SKILL.md") });
    expect(summary(result.targets)).toEqual([{ kind: "skill", path: "x", files: ["x/SKILL.md"] }]);
  });

  it("keeps settings, MCP configs and plugin manifests inside a skill folder as their own targets", async () => {
    // A repository that is itself a skill (SKILL.md at the root) still has live project settings and MCP servers.
    const root = tree({
      "SKILL.md": "---\nname: root\n---\n",
      "scripts/run.sh": "echo run\n",
      ".claude/settings.json": "{}",
      ".mcp.json": "{}",
      ".claude-plugin/plugin.json": "{}",
      "hooks/hooks.json": "{}",
      "commands/hello.md": "# stays in the skill",
    });
    const result = await discover({ path: root });
    expect(summary(result.targets)).toEqual([
      { kind: "skill", path: ".", files: ["SKILL.md", "commands/hello.md", "scripts/run.sh"] },
      { kind: "plugin-manifest", path: ".claude-plugin/plugin.json", files: [".claude-plugin/plugin.json"] },
      { kind: "settings", path: ".claude/settings.json", files: [".claude/settings.json"] },
      { kind: "mcp-config", path: ".mcp.json", files: [".mcp.json"] },
      { kind: "settings", path: "hooks/hooks.json", files: ["hooks/hooks.json"] },
    ]);
  });

  it("scans only agent config inside ~/.claude with --global", async () => {
    const home = tree({
      ".claude/CLAUDE.md": "# global",
      ".claude/settings.json": "{}",
      ".claude/skills/notes/SKILL.md": "---\nname: notes\n---\n",
      ".claude/projects/-tmp/session.jsonl": "{}",
      ".claude/projects/-tmp/CLAUDE.md": "# transcript dir, skipped",
      ".claude/plugins/cache/m/p/1.0.0/.claude-plugin/plugin.json": "{}",
      ".claude/plugins/cache/m/p/1.0.0/commands/go.md": "# go",
    });
    const empty = tree({ "README.md": "x" });
    const result = await discover({ path: empty, global: true, homeDir: home });
    expect(result.targets.map((t) => `${t.kind} ${t.path}`)).toEqual([
      "instructions ~/.claude/CLAUDE.md",
      "plugin-manifest ~/.claude/plugins/cache/m/p/1.0.0/.claude-plugin/plugin.json",
      "instructions ~/.claude/plugins/cache/m/p/1.0.0/commands/go.md",
      "settings ~/.claude/settings.json",
      "skill ~/.claude/skills/notes",
    ]);
  });

  it("does not scan ~/.claude twice when the project root contains it", async () => {
    const home = tree({ ".claude/CLAUDE.md": "# global" });
    const result = await discover({ path: home, global: true, homeDir: home });
    expect(result.targets.map((t) => t.path)).toEqual([".claude/CLAUDE.md"]);
  });

  it("does not follow symbolic links and reports them when they look like targets", async (ctx) => {
    const root = tree({ "outside/secret.txt": "x", ".claude/skills/s/SKILL.md": "---\nname: s\n---\n" });
    try {
      symlinkSync(join(root, "outside", "secret.txt"), join(root, ".claude", "skills", "s", "linked.txt"));
    } catch {
      ctx.skip(); // Creating symlinks needs extra privileges on Windows.
    }
    const result = await discover({ path: root });
    expect(result.targets[0]!.files.map((f) => f.path)).toEqual([".claude/skills/s/SKILL.md"]);
    expect(result.skipped).toEqual([{ path: ".claude/skills/s/linked.txt", reason: "symbolic link (not followed)" }]);
  });

  it("fails clearly on a missing path", async () => {
    await expect(discover({ path: join(project, "nope") })).rejects.toBeInstanceOf(DiscoveryError);
  });

  it("classifies by path", () => {
    expect(classifyFile("/p/AGENTS.md", [])).toBe("instructions");
    expect(classifyFile("/p/.claude/settings.local.json", [])).toBe("settings");
    expect(classifyFile("/p/settings.json", [])).toBeUndefined();
    expect(classifyFile("/p/commands/x.md", [])).toBeUndefined();
    expect(classifyFile("/p/commands/x.md", ["/p"])).toBe("instructions");
  });
});
