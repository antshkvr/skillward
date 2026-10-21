import { homedir } from "node:os";
import { discover } from "../discovery/index.js";
import { parseFile } from "../parsers/index.js";
import { ALL_RULES } from "../rules/index.js";
import { applyBaseline, type Baseline } from "../baseline/index.js";
import type { Config } from "../config/index.js";
import { applySuppressions, type SuppressedFinding } from "./suppressions.js";
import {
  severityRank,
  type Finding,
  type ParsedFile,
  type Rule,
  type Severity,
  type SkippedFile,
  type TargetKind,
} from "../types.js";

/** Findings of one rule in one file beyond this are collapsed into a single summary finding. */
export const MAX_FINDINGS_PER_RULE_PER_FILE = 25;

export interface ScanOptions {
  path: string;
  global?: boolean;
  /** Only the global configuration, not the project at `path` (`verify --global`). */
  globalOnly?: boolean;
  homeDir?: string;
  config: Config;
  rules?: Rule[];
  /** Only report findings in these files (absolute paths). Used by `verify` to scan what changed. */
  onlyFiles?: Set<string>;
  /** Known findings (from `--baseline`): matching ones are reported separately and don't affect the exit code. */
  baseline?: Baseline;
  /** Respect `.gitignore` files in the scanned folder (default true). */
  gitignore?: boolean;
}

export interface ScannedTarget {
  kind: TargetKind;
  path: string;
  files: string[];
}

export interface ScanError {
  ruleId?: string;
  path: string;
  message: string;
}

export interface ScanResult {
  root: string;
  /** Home directory that `~/` display paths refer to. */
  homeDir: string;
  targets: ScannedTarget[];
  findings: Finding[];
  /** Findings silenced by inline `skillward-ignore` comments. Never counted for the exit code. */
  suppressed: SuppressedFinding[];
  /** Set when a baseline was applied: findings it matched, and its entries for scanned files that matched nothing. */
  baseline?: { findings: Finding[]; stale: number };
  skipped: SkippedFile[];
  errors: ScanError[];
}

export async function scan(options: ScanOptions): Promise<ScanResult> {
  const rules = activeRules(options.rules ?? ALL_RULES, options.config);
  const discovery = await discover({
    path: options.path,
    ignore: options.config.ignore,
    global: options.global,
    globalOnly: options.globalOnly,
    homeDir: options.homeDir,
    gitignore: options.gitignore,
  });

  const findings: Finding[] = [];
  const suppressed: SuppressedFinding[] = [];
  const errors: ScanError[] = [];
  const inlineIgnore = options.config.inlineIgnore !== false;
  const only = options.onlyFiles;
  const skipped = [...discovery.skipped];
  const targets: ScannedTarget[] = [];
  const reportedFiles = new Set<string>();

  for (const target of discovery.targets) {
    if (only && !target.files.some((f) => only.has(f.absPath))) continue;
    const files: ParsedFile[] = [];
    for (const source of target.files) {
      const result = await parseFile(source);
      if (result.ok) files.push(result.file);
      else skipped.push({ path: source.path, reason: result.reason });
    }
    targets.push({ kind: target.kind, path: target.path, files: files.map((f) => f.path) });
    if (files.length === 0) continue;

    const parsed = { kind: target.kind, path: target.path, files };
    const reportable = new Set(files.filter((f) => !only || only.has(f.absPath)).map((f) => f.path));
    for (const f of reportable) reportedFiles.add(f);
    const ranges = new Map(files.filter((f) => f.lineRanges).map((f) => [f.path, f.lineRanges!]));
    const targetFindings: Finding[] = [];
    for (const { rule, severity } of rules) {
      if (!rule.appliesTo.includes(target.kind)) continue;
      let found: Finding[];
      try {
        found = rule.check(parsed);
      } catch (err) {
        errors.push({ ruleId: rule.id, path: target.path, message: (err as Error).message });
        continue;
      }
      const relevant = found.filter((f) => {
        if (!reportable.has(f.file)) return false;
        const r = ranges.get(f.file);
        return !r || r.some(([from, to]) => f.line >= from && f.line <= to);
      });
      for (const finding of capPerFile(relevant)) {
        targetFindings.push(severity ? { ...finding, severity } : finding);
      }
    }
    if (inlineIgnore) {
      const split = applySuppressions(targetFindings, files);
      findings.push(...split.active);
      suppressed.push(...split.suppressed);
    } else {
      findings.push(...targetFindings);
    }
  }

  findings.sort(compareFindings);
  suppressed.sort(compareFindings);
  const known = options.baseline ? applyBaseline(findings, options.baseline, reportedFiles) : undefined;
  return {
    root: discovery.root,
    homeDir: options.homeDir ?? homedir(),
    targets,
    findings: known ? known.active : findings,
    suppressed,
    ...(known ? { baseline: { findings: known.baselined, stale: known.stale } } : {}),
    skipped,
    errors,
  };
}

/** Rules that are not turned off, with their configured severity override, if any. */
export function activeRules(rules: Rule[], config: Config): Array<{ rule: Rule; severity?: Severity }> {
  const result: Array<{ rule: Rule; severity?: Severity }> = [];
  for (const rule of rules) {
    const setting = config.rules[rule.id];
    if (setting === "off") continue;
    result.push(setting ? { rule, severity: setting } : { rule });
  }
  return result;
}

function capPerFile(findings: Finding[]): Finding[] {
  const byFile = new Map<string, Finding[]>();
  for (const f of findings) {
    const list = byFile.get(f.file);
    if (list) list.push(f);
    else byFile.set(f.file, [f]);
  }
  const result: Finding[] = [];
  for (const list of byFile.values()) {
    list.sort(compareFindings);
    if (list.length <= MAX_FINDINGS_PER_RULE_PER_FILE) {
      result.push(...list);
      continue;
    }
    result.push(...list.slice(0, MAX_FINDINGS_PER_RULE_PER_FILE));
    const next = list[MAX_FINDINGS_PER_RULE_PER_FILE]!;
    const rest = list.length - MAX_FINDINGS_PER_RULE_PER_FILE;
    result.push({
      ...next,
      message: `${rest} more similar finding(s) in this file were collapsed (first one shown here).`,
    });
  }
  return result;
}

export function compareFindings(a: Finding, b: Finding): number {
  return (
    (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) ||
    a.line - b.line ||
    (a.column ?? 0) - (b.column ?? 0) ||
    (a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0)
  );
}

export function meetsThreshold(severity: Severity, threshold: Severity): boolean {
  return severityRank(severity) >= severityRank(threshold);
}

/** Exit code per SPEC: 1 if any finding is at or above the threshold, otherwise 0. */
export function exitCodeFor(findings: Finding[], failOn: Severity): 0 | 1 {
  return findings.some((f) => meetsThreshold(f.severity, failOn)) ? 1 : 0;
}
