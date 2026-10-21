#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { readFile, stat, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Command, CommanderError, Option } from "commander";
import { BaselineError, readBaseline, writeBaseline } from "./baseline/index.js";
import { explain } from "./capabilities/index.js";
import { ConfigError, loadConfig, type Config } from "./config/index.js";
import { DiscoveryError } from "./discovery/index.js";
import { exitCodeFor, scan } from "./engine/index.js";
import { lock, LOCK_FILE_NAME, LockError, verify } from "./lock/index.js";
import { explainJson, explainText } from "./reporters/explain.js";
import { REPORTERS, type ReportFormat } from "./reporters/index.js";
import { verifyJson, verifyText } from "./reporters/verify.js";
import { ALL_RULES } from "./rules/index.js";
import { SEVERITIES, type Severity } from "./types.js";
import { VERSION } from "./version.js";

export interface CliIO {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  /** Whether stdout is a terminal (enables colors). */
  isTTY: boolean;
  env: Record<string, string | undefined>;
  /** Overrides the home directory used by `--global` (tests). */
  homeDir?: string;
  /** Overrides the clock used for `lockedAt` (tests). */
  now?: Date;
}

const defaultIO: CliIO = {
  stdout: (t) => process.stdout.write(t),
  stderr: (t) => process.stderr.write(t),
  isTTY: Boolean(process.stdout.isTTY),
  env: process.env,
};

/** Exit codes from SPEC: 0 clean or below threshold, 1 findings at threshold, 2 run error. */
export const EXIT_OK = 0;
export const EXIT_FINDINGS = 1;
export const EXIT_ERROR = 2;

interface CommonFlags {
  format: ReportFormat;
  output?: string;
  failOn?: Severity;
  config?: string;
  color?: boolean;
  inlineIgnore?: boolean;
}

interface ExplainFlags extends Omit<CommonFlags, "format" | "failOn"> {
  format: "text" | "json";
  global?: boolean;
  all?: boolean;
}

interface ScanFlags extends CommonFlags {
  global?: boolean;
  filesFrom?: string;
  baseline?: string;
  writeBaseline?: string;
}

export async function run(argv: string[], io: CliIO = defaultIO): Promise<number> {
  let exitCode = EXIT_OK;
  const program = new Command();

  program
    .name("skillward")
    .description("Scan AI agent instruction files (SKILL.md, CLAUDE.md, AGENTS.md, MCP configs, settings, hooks, Cursor/Copilot/Gemini/Windsurf/Cline rules) for dangerous content.")
    .version(VERSION, "-v, --version")
    .exitOverride()
    .configureOutput({ writeOut: io.stdout, writeErr: io.stderr });

  const reportOptions = (cmd: Command, formats: string[]) =>
    cmd
      .addOption(new Option("--format <format>", "output format").choices(formats).default("text"))
      .option("--output <file>", "write the report to a file instead of stdout")
      .addOption(new Option("--fail-on <severity>", "lowest severity that makes the exit code 1 (default: high)").choices(SEVERITIES))
      .option("--config <file>", `config file (default: skillward.config.json in the scan root)`)
      .option("--no-inline-ignore", "ignore skillward-ignore comments (use when auditing third-party skills)")
      .option("--no-color", "disable colors");

  reportOptions(
    program
      .command("scan")
      .description("scan a project (default: current directory) for dangerous agent instructions")
      .argument("[path]", "file or directory to scan", ".")
      .option("--global", "also scan ~/.claude and the MCP servers in ~/.claude.json")
      .option("--files-from <file>", "only report findings in the files listed in <file> (one path per line, relative to the current directory); used for pull requests")
      .option("--baseline <file>", "report only findings that are not in this baseline (known findings are listed separately)")
      .option("--write-baseline <file>", "record the current findings as the baseline in <file> and exit 0"),
    Object.keys(REPORTERS),
  ).action(async (path: string, flags: ScanFlags) => {
    exitCode = await guard(io, () => runScan(path, flags, io));
  });

  program
    .command("explain")
    .description("summarize what each skill, MCP server and config lets the agent do (the permissions-screen view of scan)")
    .argument("[path]", "file or directory to explain", ".")
    .addOption(new Option("--format <format>", "output format").choices(["text", "json"]).default("text"))
    .option("--output <file>", "write the report to a file instead of stdout")
    .option("--global", "also explain ~/.claude and the MCP servers in ~/.claude.json")
    .option("--all", "also list targets with nothing notable")
    .option("--config <file>", `config file (default: skillward.config.json in the scan root)`)
    .option("--no-inline-ignore", "ignore skillward-ignore comments (use when auditing third-party skills)")
    .option("--no-color", "disable colors")
    .action(async (path: string, flags: ExplainFlags) => {
      exitCode = await guard(io, () => runExplain(path, flags, io));
    });

  program
    .command("lock")
    .description(`create or update ${LOCK_FILE_NAME} with hashes of all agent instruction files`)
    .argument("[path]", "project directory", ".")
    .option("--config <file>", `config file (default: skillward.config.json in the project)`)
    .option("--no-snapshots", "do not keep copies of locked files in .skillward/snapshots (verify then can't show diffs)")
    .action(async (path: string, flags: { config?: string; snapshots?: boolean }) => {
      exitCode = await guard(io, async () => {
        const root = await requireDirectory(path);
        const { config } = await loadConfig({ configPath: flags.config, root });
        const result = await lock({ root, config, snapshots: flags.snapshots, now: io.now });
        const files = result.lock.entries.reduce((n, e) => n + Object.keys(e.files).length, 0);
        io.stdout(
          `Locked ${result.lock.entries.length} target(s), ${files} file(s) → ${LOCK_FILE_NAME}` +
            (result.updated.length ? ` (${result.updated.length} new or updated)` : " (no changes)") +
            "\n",
        );
        return EXIT_OK;
      });
    });

  reportOptions(
    program
      .command("verify")
      .description(`compare agent instruction files with ${LOCK_FILE_NAME}, show the diff and scan what changed`)
      .argument("[path]", "project directory", "."),
    ["text", "json"],
  ).action(async (path: string, flags: CommonFlags) => {
    exitCode = await guard(io, () => runVerify(path, flags, io));
  });

  program
    .command("rules")
    .description("list available rules")
    .action(() => {
      const lines = ALL_RULES.map(
        (r) => `${r.id}  ${r.name.padEnd(26)} ${r.severity.padEnd(6)}  ${r.description}\n${" ".repeat(42)}applies to: ${r.appliesTo.join(", ")}`,
      );
      io.stdout(lines.join("\n") + "\n");
    });

  try {
    await program.parseAsync(argv, { from: "user" });
  } catch (err) {
    if (err instanceof CommanderError) {
      // --help and --version exit through here too.
      return err.exitCode === 0 ? EXIT_OK : EXIT_ERROR;
    }
    io.stderr(`skillward: ${(err as Error).message}\n`);
    return EXIT_ERROR;
  }
  return exitCode;
}

/** Maps expected user errors to exit code 2 with a one-line message. */
async function guard(io: CliIO, fn: () => Promise<number>): Promise<number> {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof ConfigError || err instanceof DiscoveryError || err instanceof LockError || err instanceof BaselineError) {
      io.stderr(`skillward: ${err.message}\n`);
      return EXIT_ERROR;
    }
    throw err;
  }
}

function withFlags(config: Config, flags: CommonFlags): Config {
  return flags.inlineIgnore === false ? { ...config, inlineIgnore: false } : config;
}

async function runScan(path: string, flags: ScanFlags, io: CliIO): Promise<number> {
  const root = resolve(path);
  const loaded = await loadConfig({ configPath: flags.config, root: (await isDirectory(root)) ? root : undefined });
  const config = withFlags(loaded.config, flags);
  const failOn = flags.failOn ?? config.failOn ?? "high";
  if (flags.writeBaseline) {
    if (flags.filesFrom || flags.baseline) {
      throw new ConfigError("--write-baseline records every current finding; it can't be combined with --files-from or --baseline");
    }
    const result = await scan({ path, global: flags.global, homeDir: io.homeDir, config });
    if (result.errors.length > 0) {
      for (const e of result.errors) io.stderr(`skillward: error ${e.ruleId ? `in ${e.ruleId} ` : ""}on ${e.path}: ${e.message}
`);
      return EXIT_ERROR;
    }
    await writeBaseline(flags.writeBaseline, result.findings);
    io.stdout(`Recorded ${result.findings.length} finding(s) as the baseline → ${flags.writeBaseline}
`);
    return EXIT_OK;
  }
  const onlyFiles = flags.filesFrom ? await readFileList(flags.filesFrom) : undefined;
  const baseline = flags.baseline ? await readBaseline(flags.baseline) : undefined;
  const result = await scan({ path, global: flags.global, homeDir: io.homeDir, config, onlyFiles, baseline });

  const report = REPORTERS[flags.format]({ result, failOn, color: useColor(flags, io) });
  await emit(report, flags, io);
  if (result.errors.length > 0) return EXIT_ERROR;
  return exitCodeFor(result.findings, failOn);
}

/** Informational: exit 0 once the summary is printed (CI gates on `scan --fail-on`), 2 on run errors. */
async function runExplain(path: string, flags: ExplainFlags, io: CliIO): Promise<number> {
  const root = resolve(path);
  const loaded = await loadConfig({ configPath: flags.config, root: (await isDirectory(root)) ? root : undefined });
  const config = withFlags(loaded.config, flags);
  const result = await scan({ path, global: flags.global, homeDir: io.homeDir, config });
  const targets = explain(result);
  const report =
    flags.format === "json"
      ? explainJson(result.root, targets)
      : explainText(result.root, targets, { color: useColor({ ...flags, format: "text" }, io), all: Boolean(flags.all) });
  await emit(report, flags, io);
  return result.errors.length > 0 ? EXIT_ERROR : EXIT_OK;
}

async function runVerify(path: string, flags: CommonFlags, io: CliIO): Promise<number> {
  const root = await requireDirectory(path);
  const loaded = await loadConfig({ configPath: flags.config, root });
  const config = withFlags(loaded.config, flags);
  const failOn = flags.failOn ?? config.failOn ?? "high";
  const result = await verify({ root, config });

  const touched = new Set(result.changes.flatMap((c) => (c.absPath ? [c.absPath] : [])));
  const scanned = touched.size ? await scan({ path: root, config, onlyFiles: touched }) : undefined;
  const ctx = { verify: result, scan: scanned, failOn, color: useColor(flags, io) };
  await emit(flags.format === "json" ? verifyJson(ctx) : verifyText(ctx), flags, io);

  if (scanned && scanned.errors.length > 0) return EXIT_ERROR;
  // Any drift from the lockfile fails: changes must be reviewed and re-locked.
  return result.changes.length > 0 ? EXIT_FINDINGS : EXIT_OK;
}

function useColor(flags: CommonFlags, io: CliIO): boolean {
  return flags.color !== false && !flags.output && io.isTTY && !io.env.NO_COLOR && flags.format === "text";
}

async function emit(report: string, flags: CommonFlags, io: CliIO): Promise<void> {
  if (flags.output) {
    await writeFile(flags.output, report, "utf8");
    io.stderr(`skillward: report written to ${flags.output}\n`);
  } else {
    io.stdout(report);
  }
}

/** Reads a newline-separated path list (e.g. `git diff --name-only` output) as absolute paths. */
async function readFileList(file: string): Promise<Set<string>> {
  let text: string;
  try {
    text = await readFile(file, "utf8");
  } catch (err) {
    throw new ConfigError(`cannot read --files-from ${file}: ${(err as Error).message}`);
  }
  const paths = text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l !== "" && !l.startsWith("#"));
  return new Set(paths.map((p) => resolve(p)));
}

async function isDirectory(path: string): Promise<boolean> {
  return stat(path).then((s) => s.isDirectory(), () => false);
}

async function requireDirectory(path: string): Promise<string> {
  const root = resolve(path);
  if (!(await isDirectory(root))) throw new DiscoveryError(`not a directory: ${path}`);
  return root;
}

function isMain(): boolean {
  if (!process.argv[1]) return false;
  try {
    // npm installs bins as symlinks/shims, so compare real paths.
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isMain()) {
  run(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (err: unknown) => {
      process.stderr.write(`skillward: unexpected error: ${(err as Error)?.stack ?? String(err)}\n`);
      process.exitCode = EXIT_ERROR;
    },
  );
}
