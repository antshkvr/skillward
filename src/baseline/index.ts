import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import type { Finding } from "../types.js";

/**
 * A baseline records the findings a project has already reviewed, so `scan --baseline` reports only new ones. Useful
 * when adding skillward to CI on an existing repository. It stores fingerprints, never snippets: a baseline must not
 * become a copy of what it hides (secrets included).
 *
 * A finding matches by rule, file and the text around the match — not the line number, so edits above it don't
 * resurface it. Editing the matched line itself makes it new again, which is the point.
 */
export const BASELINE_VERSION = 1;

export interface BaselineEntry {
  ruleId: string;
  file: string;
  /** Where it was when recorded. Informational only: matching ignores it. */
  line: number;
  fingerprint: string;
}

export interface Baseline {
  version: typeof BASELINE_VERSION;
  findings: BaselineEntry[];
}

export class BaselineError extends Error {}

const FINGERPRINT = /^[0-9a-f]{16}$/;

export function fingerprint(f: Pick<Finding, "ruleId" | "file" | "snippet" | "message">): string {
  const text = (f.snippet || f.message).replace(/\s+/g, " ").trim();
  return createHash("sha256").update(`${f.ruleId}\0${f.file}\0${text}`).digest("hex").slice(0, 16);
}

export function createBaseline(findings: Finding[]): Baseline {
  const entries = findings.map((f) => ({ ruleId: f.ruleId, file: f.file, line: f.line, fingerprint: fingerprint(f) }));
  entries.sort((a, b) => cmp(a.file, b.file) || a.line - b.line || cmp(a.ruleId, b.ruleId) || cmp(a.fingerprint, b.fingerprint));
  return { version: BASELINE_VERSION, findings: entries };
}

const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

export async function writeBaseline(path: string, findings: Finding[]): Promise<Baseline> {
  const baseline = createBaseline(findings);
  await writeFile(path, JSON.stringify(baseline, null, 2) + "\n", "utf8");
  return baseline;
}

/** Reads and validates a baseline. It comes with the repository, so it is untrusted input. */
export async function readBaseline(path: string): Promise<Baseline> {
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch (err) {
    throw new BaselineError(`cannot read baseline ${path}: ${(err as Error).message}`);
  }
  let data: unknown;
  try {
    data = JSON.parse(raw.replace(/^\uFEFF/, ""));
  } catch (err) {
    throw new BaselineError(`invalid JSON in baseline ${path}: ${(err as Error).message}`);
  }
  return validateBaseline(data, path);
}

export function validateBaseline(data: unknown, source = "baseline"): Baseline {
  const fail = (msg: string): never => {
    throw new BaselineError(`${source}: ${msg}`);
  };
  if (typeof data !== "object" || data === null || Array.isArray(data)) fail("must be a JSON object");
  const obj = data as Record<string, unknown>;
  if (obj.version !== BASELINE_VERSION) fail(`unsupported version ${JSON.stringify(obj.version)} (expected ${BASELINE_VERSION})`);
  if (!Array.isArray(obj.findings)) fail(`"findings" must be an array`);
  const findings = (obj.findings as unknown[]).map((e, i) => {
    const entry = e as Partial<BaselineEntry> | null;
    if (
      typeof entry !== "object" ||
      entry === null ||
      typeof entry.ruleId !== "string" ||
      typeof entry.file !== "string" ||
      !Number.isInteger(entry.line) ||
      typeof entry.fingerprint !== "string" ||
      !FINGERPRINT.test(entry.fingerprint)
    ) {
      return fail(`findings[${i}] must have ruleId, file, line and a 16-hex-digit fingerprint`);
    }
    return { ruleId: entry.ruleId, file: entry.file, line: entry.line!, fingerprint: entry.fingerprint };
  });
  return { version: BASELINE_VERSION, findings };
}

/**
 * Splits findings into new and known. Each entry matches at most one finding, so a second copy of a known line is
 * new. `stale` counts entries in the given files that matched nothing (fixed, or the line changed): entries for files
 * outside this scan (another path, no `--global`, a pull request's unchanged files) aren't counted.
 */
export function applyBaseline(
  findings: Finding[],
  baseline: Baseline,
  scannedFiles: Set<string>,
): { active: Finding[]; baselined: Finding[]; stale: number } {
  const remaining = new Map<string, number>();
  for (const e of baseline.findings) {
    const key = `${e.ruleId}\0${e.file}\0${e.fingerprint}`;
    remaining.set(key, (remaining.get(key) ?? 0) + 1);
  }
  const active: Finding[] = [];
  const baselined: Finding[] = [];
  for (const f of findings) {
    const key = `${f.ruleId}\0${f.file}\0${fingerprint(f)}`;
    const left = remaining.get(key) ?? 0;
    if (left > 0) {
      remaining.set(key, left - 1);
      baselined.push(f);
    } else {
      active.push(f);
    }
  }
  let stale = 0;
  for (const [key, left] of remaining) {
    if (left > 0 && scannedFiles.has(key.split("\0")[1]!)) stale += left;
  }
  return { active, baselined, stale };
}
