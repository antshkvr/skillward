import { lstat, readFile } from "node:fs/promises";
import { basename, dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { parse } from "smol-toml";

/** A local script that a hook command runs. */
export interface HookTarget {
  absPath: string;
  event: string;
}

/** Interpreters and wrappers that take a script path as their first non-option argument. */
const RUNNERS = new Set([
  "node", "nodejs", "deno", "bun", "tsx", "ts-node", "python", "python3", "py", "ruby", "perl", "php", "lua",
  "bash", "sh", "zsh", "dash", "ksh", "fish", "pwsh", "powershell", "cmd", "source", ".", "exec", "env", "uv", "run",
  "npx", "bunx", "nohup", "timeout", "time",
]);
const SCRIPT_EXTENSIONS = /\.(?:sh|bash|zsh|fish|command|ps1|psm1|bat|cmd|py|js|mjs|cjs|ts|mts|cts|rb|pl|php|lua|exe|bin)$/i;

/**
 * Local scripts the hooks of a settings / hooks / plugin.json file run. Only paths inside `scanRoot` that are regular
 * files (not symlinks) are returned. Paths are resolved against the project (the folder holding `.claude/`) for
 * project settings, or against the plugin root for plugin hooks. Never executes anything.
 */
export async function hookTargets(file: string, scanRoot: string, home?: string): Promise<HookTarget[]> {
  const out: HookTarget[] = [];
  for (const hook of await hookScriptPaths(file, scanRoot, home)) {
    const isFile = await lstat(hook.absPath).then((s) => s.isFile(), () => false);
    if (isFile) out.push(hook);
  }
  return out;
}

/** The script paths inside `scanRoot` that the hooks of `file` name, whether or not they exist on disk. */
export async function hookScriptPaths(file: string, scanRoot: string, home?: string): Promise<HookTarget[]> {
  let value: unknown;
  try {
    const text = await readFile(file, "utf8");
    // Codex `config.toml` declares hooks (and `notify`) in TOML; parsed as data, nothing is run.
    value = file.endsWith(".toml") ? parse(text) : JSON.parse(text);
  } catch {
    return [];
  }
  const base = baseDirFor(file, home);
  const out: HookTarget[] = [];
  for (const { event, command } of commandsOf(value)) {
    const path = scriptPath(command, base, home);
    if (!path) continue;
    const rel = relative(scanRoot, path);
    if (rel === "" || rel.startsWith("..") || isAbsolute(rel)) continue;
    out.push({ absPath: path, event });
  }
  return out;
}

/** `<project>/.claude/settings.json` → `<project>`; `<plugin>/hooks/hooks.json` and `.claude-plugin/plugin.json` → `<plugin>`. */
function baseDirFor(file: string, home?: string): string {
  const dir = dirname(file);
  // Cursor runs user hooks (`~/.cursor/hooks.json`) from `~/.cursor`; relative paths in `~/.codex/hooks.json` are read there too.
  if (home !== undefined && (dir === resolve(home, ".cursor") || dir === resolve(home, ".codex"))) return dir;
  const name = dir.split(sep).pop();
  // Cursor and Codex run project hooks from the project root (`.cursor/hooks/x.sh`, `.codex/hooks/x.py` paths).
  return name === ".claude" || name === "hooks" || name === ".claude-plugin" || name === ".cursor" || name === ".codex" ? dirname(dir) : dir;
}

function commandsOf(value: unknown): Array<{ event: string; command: string }> {
  const out: Array<{ event: string; command: string }> = [];
  if (!value || typeof value !== "object") return out;
  const obj = value as Record<string, unknown>;
  const hooks = obj.hooks;
  if (hooks && typeof hooks === "object" && !Array.isArray(hooks)) {
    for (const [event, groups] of Object.entries(hooks as Record<string, unknown>)) {
      if (!Array.isArray(groups)) continue;
      for (const group of groups) {
        // Cursor: `{event: [{command}]}`; Claude Code: `{event: [{matcher, hooks: [{command}]}]}`.
        const list = (group as { hooks?: unknown })?.hooks;
        for (const hook of [group, ...(Array.isArray(list) ? list : [])]) {
          // Codex handlers may add a Windows-only `commandWindows`.
          for (const key of ["command", "commandWindows"]) {
            const command = (hook as Record<string, unknown> | undefined)?.[key];
            if (typeof command === "string") out.push({ event, command });
          }
        }
      }
    }
  }
  const status = (obj.statusLine as { command?: unknown } | undefined)?.command;
  if (typeof status === "string") out.push({ event: "statusLine", command: status });
  // Codex `notify = ["python3", "notify.py"]`: a program and its arguments.
  if (Array.isArray(obj.notify) && obj.notify.length > 0 && obj.notify.every((a) => typeof a === "string")) {
    out.push({ event: "notify", command: (obj.notify as string[]).map((a) => (/\s/.test(a) ? `"${a}"` : a)).join(" ") });
  }
  return out;
}

/** The first argument that names a local script, with `$CLAUDE_PROJECT_DIR` / `$CLAUDE_PLUGIN_ROOT` substituted. */
export function scriptPath(command: string, base: string, home?: string): string | undefined {
  // Only the first command of a pipeline/list: that's what runs first and what reviewers look at.
  // Codex names repo-local hooks from the git root: `"$(git rev-parse --show-toplevel)/.codex/hooks/x.py"`.
  const rooted = command.replace(/\$\(\s*git rev-parse --show-toplevel\s*\)/g, ".");
  const first = rooted.split(/\s*(?:&&|\|\||[;|])\s*/)[0] ?? "";
  const words = tokenize(first);
  for (const raw of words) {
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(raw)) continue; // VAR=value
    let word = raw
      .replace(/\$\{CLAUDE_PROJECT_DIR\}|\$CLAUDE_PROJECT_DIR\b|\$\{CLAUDE_PLUGIN_ROOT\}|\$CLAUDE_PLUGIN_ROOT\b/g, ".")
      .replace(/^%CLAUDE_PROJECT_DIR%|^%CLAUDE_PLUGIN_ROOT%/i, ".");
    if (home) word = word.replace(/^(?:~|\$HOME|\$\{HOME\})(?=\/)/, home.split("\\").join("/"));
    if (word.startsWith("-") || /^\/[a-z]$/i.test(word)) continue; // options, incl. `cmd /c`
    // `/usr/bin/python3 x.py`, `/usr/bin/env node x.mjs`: an interpreter named by its path is still an interpreter.
    if (RUNNERS.has(word.toLowerCase()) || (word.includes("/") && RUNNERS.has(basename(word).toLowerCase()))) continue;
    if (/[$`*?]|^~/.test(word)) return undefined; // a variable or glob: not resolvable statically
    // Absolute paths are kept; hookTargets() drops the ones outside the scan root.
    if (isAbsolute(word) || /^[A-Za-z]:[\\/]/.test(word)) return resolve(word);
    if (word.includes("/") || word.includes("\\") || SCRIPT_EXTENSIONS.test(word)) return resolve(base, word);
    return undefined; // a command name (`prettier`, `jq`): not a local script
  }
  return undefined;
}

/** Splits a command line on spaces, honoring single and double quotes. */
function tokenize(command: string): string[] {
  const words: string[] = [];
  const re = /"((?:[^"\\]|\\.)*)"|'([^']*)'|(\S+)/g;
  let m: RegExpExecArray | null;
  let current = "";
  let lastEnd = -1;
  while ((m = re.exec(command))) {
    const part = m[1] ?? m[2] ?? m[3] ?? "";
    // Adjacent pieces form one word: "${CLAUDE_PROJECT_DIR}"/.claude/hooks/x.sh
    if (m.index === lastEnd) current += part;
    else {
      if (lastEnd !== -1) words.push(current);
      current = part;
    }
    lastEnd = m.index + m[0].length;
  }
  if (lastEnd !== -1) words.push(current);
  return words;
}
