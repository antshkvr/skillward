import { lstat, readdir, readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import ignore, { type Ignore } from "ignore";
import type { SkippedFile, SourceFile, Target, TargetKind } from "../types.js";
import { hookTargets } from "./hook-targets.js";

export interface DiscoveryOptions {
  /** File or directory to scan. */
  path: string;
  /** gitignore-style patterns from the config, relative to the scan root. */
  ignore?: string[];
  /** Also scan `~/.claude`. */
  global?: boolean;
  /** Only the global configuration: `path` is the home directory and is not walked (`lock`/`verify --global`). */
  globalOnly?: boolean;
  /** Overrides the home directory (tests). */
  homeDir?: string;
  /** Respect `.gitignore` files (default true). Off for `--untrusted`: the scanned folder's own files decide nothing. */
  gitignore?: boolean;
}

export interface DiscoveryResult {
  /** Absolute scan root directory. */
  root: string;
  targets: Target[];
  skipped: SkippedFile[];
}

export class DiscoveryError extends Error {}

/** Directories that are never entered. `.skillward` holds lockfile snapshots — old copies, not live config. */
const ALWAYS_SKIPPED_DIRS = new Set(["node_modules", ".git", ".hg", ".svn", ".skillward"]);

/**
 * Agent configuration that is often gitignored on purpose (local settings and memory) but is still
 * loaded by the agent, so `.gitignore` does not hide it from the scan. Config `ignore` still applies.
 */
const AGENT_DIRS = new Set([".claude", ".claude-plugin", ".cursor", ".windsurf", ".gemini", ".kiro", ".clinerules", ".codex"]);
/** Instruction files recognized by name at any depth (Claude Code, AGENTS.md, Gemini CLI, Cursor, Windsurf, Cline). */
const INSTRUCTION_FILES = new Set(["CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "GEMINI.md", ".cursorrules", ".windsurfrules", ".clinerules"]);
const GITIGNORE_EXEMPT_FILES = new Set([...INSTRUCTION_FILES, ".mcp.json"]);

/**
 * User-level agent configuration `--global` reads (SPEC section 5): a folder under the home directory and the only
 * top-level entries walked in it — the rest (transcripts, caches, credentials, task history) is not agent config.
 * `kinds` classifies paths, relative to the folder, that `classifyFile` doesn't know.
 */
interface GlobalSource {
  dir: string;
  entries: string[];
  kinds?: Array<[RegExp, TargetKind]>;
}

const CLINE_MCP: Pick<GlobalSource, "entries" | "kinds"> = { entries: ["cline_mcp_settings.json"], kinds: [[/^cline_mcp_settings\.json$/, "mcp-config"]] };

const GLOBAL_SOURCES: GlobalSource[] = [
  { dir: ".claude", entries: ["CLAUDE.md", "settings.json", "settings.local.json", "skills", "agents", "commands", "plugins"] },
  { dir: ".cursor", entries: ["mcp.json", "hooks.json", "commands", "skills"] },
  { dir: ".gemini", entries: ["settings.json", "GEMINI.md", "commands", "extensions"] },
  {
    dir: ".codeium/windsurf",
    entries: ["mcp_config.json", "memories", "global_workflows"],
    kinds: [[/^mcp_config\.json$/, "mcp-config"], [/^memories\/global_rules\.md$/, "instructions"], [/^global_workflows\/.+\.md$/, "instructions"]],
  },
  { dir: ".cline/data/settings", ...CLINE_MCP },
  // Older Cline versions kept MCP servers in the VS Code extension's storage (Windows, macOS, Linux).
  ...["AppData/Roaming/Code", "Library/Application Support/Code", ".config/Code"].map((app) => ({
    dir: `${app}/User/globalStorage/saoudrizwan.claude-dev/settings`,
    ...CLINE_MCP,
  })),
  { dir: ".cline", entries: ["rules", "workflows", "skills"], kinds: [[/^(?:rules|workflows)\/.+\.md$/, "instructions"]] },
  { dir: "Documents/Cline", entries: ["Rules", "Workflows"], kinds: [[/^(?:Rules|Workflows)\/.+\.md$/, "instructions"]] },
  { dir: ".agents", entries: ["AGENTS.md", "skills"] },
  { dir: ".kiro", entries: ["settings", "steering"] },
  { dir: ".codex", entries: ["AGENTS.md", "skills", "hooks.json", "config.toml"] },
];

/** A folder global files came from: hook scripts of its files resolve inside it and display under its prefix. */
interface GlobalScope {
  abs: string;
  display: string;
}

interface WalkedFile extends SourceFile {
  /** Absolute path with forward slashes, used for classification. */
  classifyPath: string;
  symlink: boolean;
}

export async function discover(options: DiscoveryOptions): Promise<DiscoveryResult> {
  const input = resolve(options.path);
  let inputStat;
  try {
    inputStat = await lstat(input);
  } catch {
    throw new DiscoveryError(`path not found: ${options.path}`);
  }

  const targets: Target[] = [];
  const skipped: SkippedFile[] = [];
  let root: string;

  if (options.globalOnly) {
    root = input;
  } else if (inputStat.isFile() || inputStat.isSymbolicLink()) {
    if (inputStat.isSymbolicLink()) throw new DiscoveryError(`refusing to follow symbolic link: ${options.path}`);
    root = dirname(input);
    if (basename(input) === "SKILL.md") {
      const files = await walk(root, { displayPrefix: basename(root) }, skipped);
      targets.push(...classify(files, skipped));
    } else {
      const file = toWalked(input, basename(input), false);
      const kind = classifyFile(file.classifyPath, []) ?? "instructions";
      targets.push({ kind, path: file.path, files: [file] });
    }
  } else if (inputStat.isDirectory()) {
    root = input;
    const files = await walk(root, { configIgnore: options.ignore ?? [], useGitignore: options.gitignore !== false }, skipped);
    targets.push(...classify(files, skipped));
  } else {
    throw new DiscoveryError(`not a file or directory: ${options.path}`);
  }

  const globalScopes: GlobalScope[] = [];
  if (options.global || options.globalOnly) {
    const home = options.homeDir ?? homedir();
    // Avoid scanning the same files twice when the project root already contains ~/.claude.
    const seen = new Set(targets.flatMap((t) => t.files.map((f) => f.absPath)));
    for (const source of GLOBAL_SOURCES) {
      const dir = join(home, source.dir);
      const exists = await lstat(dir).then((s) => s.isDirectory(), () => false);
      if (!exists) continue;
      const display = `~/${source.dir}`;
      const files = await walk(dir, { displayPrefix: display, topLevel: new Set(source.entries) }, skipped);
      const prefix = dir.split(sep).join("/") + "/";
      const kindOf = (file: WalkedFile) => source.kinds?.find(([re]) => re.test(file.classifyPath.slice(prefix.length)))?.[1];
      targets.push(...classify(files.filter((f) => !seen.has(f.absPath)), skipped, kindOf));
      globalScopes.push({ abs: dir, display });
    }
    // User- and project-scoped MCP servers live in ~/.claude.json (next to history, which is not scanned).
    const claudeJson = join(home, ".claude.json");
    const isFile = await lstat(claudeJson).then((s) => s.isFile(), () => false);
    if (isFile && !seen.has(claudeJson)) {
      targets.push({ kind: "mcp-config", path: "~/.claude.json", files: [{ absPath: claudeJson, path: "~/.claude.json" }] });
    }
  }

  await attachHookTargets(targets, root, globalScopes, options.homeDir ?? homedir());

  targets.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return { root, targets, skipped };
}

/** Files whose `hooks` (and `statusLine`) commands can name local scripts; matched on forward-slash paths. */
export const HOOK_FILE = /(?:^|\/)(?:\.claude\/settings(?:\.local)?\.json|hooks\/hooks\.json|\.claude-plugin\/plugin\.json|\.cursor\/hooks\.json|\.codex\/(?:hooks\.json|config\.toml))$/;

/**
 * Adds the local scripts that hooks run to the hook file's target (see SPEC, "Hook targets"), so their content is
 * scanned and locked. A script already in a target is left where it is; in a skill it is marked as a hook target there.
 */
async function attachHookTargets(targets: Target[], root: string, globalScopes: GlobalScope[], home: string): Promise<void> {
  const owned = new Set(targets.flatMap((t) => t.files.map((f) => f.absPath)));
  const inSkills = new Map(targets.filter((t) => t.kind === "skill").flatMap((t) => t.files.map((f) => [f.absPath, f] as const)));
  for (const target of targets) {
    if (target.kind !== "settings" && target.kind !== "plugin-manifest") continue;
    for (const file of [...target.files]) {
      const forward = file.absPath.split(sep).join("/");
      if (!HOOK_FILE.test(forward)) continue;
      const global = file.path.startsWith("~/") ? globalScopes.find((s) => file.absPath.startsWith(s.abs + sep)) : undefined;
      const scope = global ? global.abs : root;
      const added = new Map<string, SourceFile>();
      for (const hook of await hookTargets(file.absPath, scope, home)) {
        const existing = added.get(hook.absPath);
        if (existing) {
          if (!existing.hookTarget!.events.includes(hook.event)) existing.hookTarget!.events.push(hook.event);
          continue;
        }
        const skillFile = inSkills.get(hook.absPath);
        if (skillFile && !skillFile.hookTarget) {
          skillFile.hookTarget = { events: [hook.event], from: file.path };
          added.set(hook.absPath, skillFile);
          continue;
        }
        if (owned.has(hook.absPath)) continue;
        const rel = relative(scope, hook.absPath).split(sep).join("/");
        const source: SourceFile = {
          absPath: hook.absPath,
          path: global ? `${global.display}/${rel}` : rel,
          hookTarget: { events: [hook.event], from: file.path },
        };
        added.set(hook.absPath, source);
        owned.add(hook.absPath);
        target.files.push(source);
      }
    }
  }
}

interface WalkOptions {
  /** Prefix for display paths instead of paths relative to the walk root. */
  displayPrefix?: string;
  configIgnore?: string[];
  useGitignore?: boolean;
  /** Only these entries are entered at the top level. */
  topLevel?: Set<string>;
}

interface GitignoreLayer {
  /** Directory of the .gitignore, relative to the walk root ("" for the root). */
  base: string;
  ig: Ignore;
}

async function walk(walkRoot: string, options: WalkOptions, skipped: SkippedFile[]): Promise<WalkedFile[]> {
  const files: WalkedFile[] = [];
  const configIg = options.configIgnore?.length ? ignore().add(options.configIgnore) : undefined;
  const display = (rel: string) => (options.displayPrefix ? `${options.displayPrefix}/${rel}` : rel);

  const visit = async (dirAbs: string, dirRel: string, layers: GitignoreLayer[], inAgentDir: boolean) => {
    let entries;
    try {
      entries = await readdir(dirAbs, { withFileTypes: true });
    } catch (err) {
      skipped.push({ path: display(dirRel || "."), reason: `cannot read directory: ${(err as Error).message}` });
      return;
    }

    if (options.useGitignore && entries.some((e) => e.name === ".gitignore" && e.isFile())) {
      try {
        const content = await readFile(join(dirAbs, ".gitignore"), "utf8");
        layers = [...layers, { base: dirRel, ig: ignore().add(content) }];
      } catch {
        // An unreadable .gitignore just means nothing is ignored by it.
      }
    }

    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const entry of entries) {
      if (dirRel === "" && options.topLevel && !options.topLevel.has(entry.name)) continue;
      const rel = dirRel ? `${dirRel}/${entry.name}` : entry.name;
      const abs = join(dirAbs, entry.name);
      const isDir = entry.isDirectory();

      if (isDir && ALWAYS_SKIPPED_DIRS.has(entry.name)) continue;
      const testPath = isDir ? `${rel}/` : rel;
      if (configIg?.ignores(testPath)) continue;
      const agentDir = inAgentDir || (isDir && AGENT_DIRS.has(entry.name));
      const exempt = agentDir || (!isDir && GITIGNORE_EXEMPT_FILES.has(entry.name));
      if (!exempt && isGitignored(layers, testPath)) continue;

      if (entry.isSymbolicLink()) {
        // Never follow links: they can point outside the project (e.g. at ~/.ssh) or loop.
        files.push(toWalked(abs, display(rel), true));
      } else if (isDir) {
        await visit(abs, rel, layers, agentDir);
      } else if (entry.isFile()) {
        files.push(toWalked(abs, display(rel), false));
      }
    }
  };

  await visit(walkRoot, "", [], false);
  return files;
}

function isGitignored(layers: GitignoreLayer[], path: string): boolean {
  for (const { base, ig } of layers) {
    const local = base ? path.slice(base.length + 1) : path;
    if (local && ig.ignores(local)) return true;
  }
  return false;
}

function toWalked(abs: string, display: string, symlink: boolean): WalkedFile {
  return { absPath: abs, path: display, classifyPath: abs.split(sep).join("/"), symlink };
}

const CONFIG_KINDS = new Set<TargetKind>(["settings", "mcp-config", "plugin-manifest"]);

/** Groups walked files into targets. Files that are not agent configuration are dropped. */
function classify(files: WalkedFile[], skipped: SkippedFile[], kindOf?: (file: WalkedFile) => TargetKind | undefined): Target[] {
  const isSkillFile = (f: WalkedFile) => !f.symlink && f.classifyPath.endsWith("/SKILL.md");
  const skillRoots = files
    .filter(isSkillFile)
    .map((f) => ({ dir: f.classifyPath.slice(0, -"/SKILL.md".length), display: parentDisplay(f.path) }))
    // Deepest first, so a file belongs to its nearest skill.
    .sort((a, b) => b.dir.length - a.dir.length);
  const pluginRoots = files
    .filter((f) => f.classifyPath.endsWith("/.claude-plugin/plugin.json"))
    .map((f) => f.classifyPath.slice(0, -"/.claude-plugin/plugin.json".length));

  const skills = new Map<string, Target>();
  const targets: Target[] = [];

  for (const file of files) {
    const own = kindOf?.(file) ?? classifyFile(file.classifyPath, pluginRoots);
    // Settings, MCP configs and plugin manifests are loaded by the agent wherever they sit, even in a skill folder.
    const skill = own && CONFIG_KINDS.has(own) ? undefined : skillRoots.find((s) => file.classifyPath.startsWith(s.dir + "/"));
    const kind: TargetKind | undefined = skill ? "skill" : own;
    if (!kind) continue;
    if (file.symlink) {
      skipped.push({ path: file.path, reason: "symbolic link (not followed)" });
      continue;
    }
    const source: SourceFile = { absPath: file.absPath, path: file.path };
    if (skill) {
      let target = skills.get(skill.dir);
      if (!target) {
        target = { kind: "skill", path: skill.display, files: [] };
        skills.set(skill.dir, target);
        targets.push(target);
      }
      target.files.push(source);
    } else {
      targets.push({ kind, path: file.path, files: [source] });
    }
  }
  return targets;
}

function parentDisplay(path: string): string {
  const idx = path.lastIndexOf("/");
  return idx === -1 ? "." : path.slice(0, idx);
}

/** Instruction files of other agents, by path (see SPEC section 5, "Other agents"). */
const OTHER_AGENT_INSTRUCTIONS = [
  /\/\.cursor\/rules\/.+\.(?:mdc|md)$/,
  /\/\.cursor\/commands\/.+\.md$/,
  /\/\.github\/copilot-instructions\.md$/,
  /\/\.github\/instructions\/.+\.instructions\.md$/,
  /\/\.github\/prompts\/.+\.prompt\.md$/,
  /\/\.github\/chatmodes\/.+\.chatmode\.md$/,
  /\/\.github\/agents\/.+\.agent\.md$/,
  /\/\.windsurf\/(?:rules|workflows)\/.+\.md$/,
  /\/\.clinerules\/.+\.md$/,
  /\/\.kiro\/steering\/.+\.md$/,
  /\/\.gemini\/commands\/.+\.toml$/,
  /\/\.gemini\/extensions\/[^/]+\/commands\/.+\.toml$/,
];

/** Target kind of a standalone file, by its absolute forward-slash path. */
export function classifyFile(path: string, pluginRoots: string[]): TargetKind | undefined {
  const name = path.slice(path.lastIndexOf("/") + 1);
  if (INSTRUCTION_FILES.has(name)) return "instructions";
  if (/\/\.claude\/(commands|agents)\/.+\.md$/.test(path)) return "instructions";
  if (OTHER_AGENT_INSTRUCTIONS.some((re) => re.test(path))) return "instructions";
  if (/\/\.(?:cursor|vscode)\/mcp\.json$|\/\.gemini\/settings\.json$|\/\.kiro\/settings\/mcp\.json$/.test(path)) return "mcp-config";
  // Gemini CLI extensions are installable third-party packages that bring their own MCP servers.
  if (/\/\.gemini\/extensions\/[^/]+\/gemini-extension\.json$/.test(path)) return "mcp-config";
  if (/\/\.(?:cursor|codex)\/hooks\.json$|\/\.codex\/config\.toml$/.test(path)) return "settings";
  if (name === ".mcp.json" || name === ".claude.json") return "mcp-config";
  if (/\/\.claude\/settings(\.local)?\.json$/.test(path)) return "settings";
  if (/\/\.claude-plugin\/(plugin|marketplace)\.json$/.test(path)) return "plugin-manifest";
  for (const plugin of pluginRoots) {
    if (!path.startsWith(plugin + "/")) continue;
    const inner = path.slice(plugin.length + 1);
    if (/^(commands|agents)\/.+\.md$/.test(inner)) return "instructions";
    if (inner === "hooks/hooks.json") return "settings";
  }
  return undefined;
}
