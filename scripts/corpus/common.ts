// Shared I/O for the corpus scripts. The corpus is third-party content: it is only ever read as data.
import { execFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

/** `--dir <path>` or `SKILLWARD_CORPUS`, default `../skillward-corpus` next to this repository (never inside it). */
export function corpusArgs<T extends Record<string, { type: "string" | "boolean"; default?: string | boolean; multiple?: boolean }>>(
  options: T,
) {
  const values = parseArgs({ options: { dir: { type: "string" }, ...options }, strict: true }).values as Record<
    string,
    string | boolean | string[] | undefined
  >;
  const dir = resolve((values.dir as string | undefined) ?? process.env.SKILLWARD_CORPUS ?? join(REPO_ROOT, "..", "skillward-corpus"));
  if (dir === REPO_ROOT || dir.startsWith(REPO_ROOT + "\\") || dir.startsWith(REPO_ROOT + "/")) {
    throw new Error(`corpus directory must be outside the skillward repository: ${dir}`);
  }
  return { dir, values };
}

export const paths = (dir: string) => ({
  candidates: join(dir, "repos.json"),
  checkouts: join(dir, "repos"),
  meta: join(dir, "meta"),
  results: join(dir, "results"),
});

export async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, "utf8")) as T;
}

export async function writeJson(path: string, data: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, JSON.stringify(data, null, 2) + "\n");
}

export interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

export function run(cmd: string, args: string[], options: { cwd?: string; input?: string; timeoutMs?: number } = {}): Promise<RunResult> {
  return new Promise((done) => {
    const child = execFile(
      cmd,
      args,
      {
        cwd: options.cwd,
        timeout: options.timeoutMs ?? 120_000,
        maxBuffer: 256 * 1024 * 1024,
        windowsHide: true,
        // Never prompt for credentials (deleted/private repos) and never run LFS smudge filters.
        env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_LFS_SKIP_SMUDGE: "1", GCM_INTERACTIVE: "never" },
      },
      (err, stdout, stderr) => {
        const code = err ? (typeof err.code === "number" ? err.code : 1) : 0;
        done({ code, stdout: String(stdout), stderr: String(stderr) || (err && !stderr ? err.message : "") });
      },
    );
    if (options.input !== undefined) child.stdin?.end(options.input);
  });
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
