// Pure helpers for the corpus research scripts (discover → fetch → scan). No I/O here, so they are unit-tested.
import { createHash } from "node:crypto";
import { classifyFile } from "../../src/discovery/index.js";
import { SEVERITIES, type Severity } from "../../src/types.js";

/** `owner/repo` → directory name used for the checkout, metadata and results. */
export function repoDirName(repo: string): string {
  // Windows can't create names ending in a dot ("owner/C.E.O.").
  return repo.replace("/", "__").replace(/\.+$/, (dots) => "_".repeat(dots.length));
}

const REPO_NAME = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9._-]{1,100}$/;

export function isRepoName(value: string): boolean {
  return REPO_NAME.test(value) && !value.endsWith("/.") && !value.endsWith("/..");
}

/** First path segments of github.com URLs that are site pages, not repository owners. */
const NOT_OWNERS = new Set([
  "about", "apps", "collections", "contact", "customer-stories", "enterprise", "events", "explore", "features",
  "login", "marketplace", "new", "notifications", "orgs", "organizations", "pricing", "security", "settings",
  "sponsors", "topics", "trending", "users", "site", "readme", "join", "codespaces", "copilot",
  "user-attachments",
]);

/** Repositories linked from a Markdown document (an awesome list), in order of first appearance. */
export function parseRepoLinks(markdown: string): string[] {
  const seen = new Set<string>();
  const order: string[] = [];
  const re = /https?:\/\/(?:www\.)?github\.com\/([A-Za-z0-9-]+)\/([A-Za-z0-9._-]+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(markdown))) {
    const owner = m[1]!;
    const name = m[2]!.replace(/\.git$/, "").replace(/[.]+$/, "");
    if (NOT_OWNERS.has(owner.toLowerCase()) || !name) continue;
    const repo = `${owner}/${name}`;
    const key = repo.toLowerCase();
    if (!isRepoName(repo) || seen.has(key)) continue;
    seen.add(key);
    order.push(repo);
  }
  return order;
}

/** Stable pseudo-random order, so a capped sample does not depend on search ranking. */
export function sampleKey(repo: string): string {
  return createHash("sha256").update(repo.toLowerCase()).digest("hex");
}

export interface Candidate {
  repo: string;
  /** Where the repo came from: `seed`, `list:<repo>`, `search:<query>`. */
  sources: string[];
}

/**
 * Merges candidates by repo (case-insensitive) and caps the total. Seeds and awesome-list links are kept first;
 * search hits fill the rest in `sampleKey` order.
 */
export function selectCandidates(groups: { priority: boolean; candidates: Candidate[] }[], max: number): Candidate[] {
  const merged = new Map<string, Candidate & { priority: boolean }>();
  for (const group of groups) {
    for (const c of group.candidates) {
      const key = c.repo.toLowerCase();
      const existing = merged.get(key);
      if (existing) {
        for (const s of c.sources) if (!existing.sources.includes(s)) existing.sources.push(s);
        existing.priority ||= group.priority;
      } else {
        merged.set(key, { repo: c.repo, sources: [...c.sources], priority: group.priority });
      }
    }
  }
  const all = [...merged.values()];
  const priority = all.filter((c) => c.priority);
  const rest = all.filter((c) => !c.priority).sort((a, b) => (sampleKey(a.repo) < sampleKey(b.repo) ? -1 : 1));
  return [...priority, ...rest].slice(0, max).map(({ repo, sources }) => ({ repo, sources }));
}

/** Extensions that are never agent instructions; skipped to save bandwidth (skillward skips binaries anyway). */
const BINARY_EXTENSIONS = new Set([
  "png", "jpg", "jpeg", "gif", "webp", "ico", "bmp", "svgz", "pdf", "zip", "gz", "tgz", "bz2", "xz", "7z", "rar",
  "jar", "woff", "woff2", "ttf", "otf", "eot", "mp3", "mp4", "mov", "wav", "ogg", "webm", "avi", "psd", "sketch",
  "fig", "exe", "dll", "so", "dylib", "bin", "wasm", "pyc", "class", "o", "a", "docx", "xlsx", "pptx", "parquet",
  "sqlite", "db", "onnx", "pt", "safetensors", "ckpt", "npy", "npz", "pkl",
]);

const WINDOWS_RESERVED = /^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$/i;

/**
 * Paths that are safe to write on every platform. The fetch step turns off git's own NTFS path checks (they reject
 * the whole checkout when any file in the repo has a `:` in its name), so this check must also cover what they
 * protect against: names that alias `.git` (`.git`, `GIT~1`, trailing dots/spaces, alternate data streams).
 */
export function isPortablePath(path: string): boolean {
  return path.split("/").every(
    (seg) =>
      seg.length > 0 &&
      !/[<>:"|?*\\\x00-\x1f]/.test(seg) &&
      !/[. ]$/.test(seg) &&
      !WINDOWS_RESERVED.test(seg) &&
      !/^(?:\.git|git~\d+)$/i.test(seg),
  );
}

export interface FileSelection {
  files: string[];
  /** Files dropped because of `maxFiles`. */
  truncated: number;
  /** Files dropped because they cannot be checked out on this platform. */
  unportable: number;
}

/**
 * Picks, from a repository tree listing, the files skillward's discovery would scan: everything inside skill
 * directories plus standalone agent files (instructions, MCP configs, settings, plugin manifests and hooks).
 */
export function selectAgentFiles(paths: string[], options: { maxFiles: number; portable?: boolean }): FileSelection {
  // classifyFile matches absolute forward-slash paths; a fake root makes `/.claude/` match at the repo root too.
  const abs = (p: string) => `/r/${p}`;
  const dirOf = (p: string) => (p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "");
  // Lookups go through each path's parent directories, not through every skill or plugin: trees of 100k+ files with
  // thousands of skills would otherwise take billions of comparisons.
  const ancestors = (p: string) => {
    const out: string[] = [];
    for (let i = p.lastIndexOf("/"); i > 0; i = p.lastIndexOf("/", i - 1)) out.push(p.slice(0, i));
    return out;
  };
  const skillDirs = new Set(paths.filter((p) => p === "SKILL.md" || p.endsWith("/SKILL.md")).map(dirOf));
  const pluginDirs = paths
    .filter((p) => p === ".claude-plugin/plugin.json" || p.endsWith("/.claude-plugin/plugin.json"))
    .map((p) => p.slice(0, -".claude-plugin/plugin.json".length).replace(/\/$/, ""));
  const pluginIndex = new Map(pluginDirs.map((d, i) => [d, i]));
  const inSkill = (p: string) => skillDirs.has("") || ancestors(p).some((d) => skillDirs.has(d));
  // Scripts hooks run usually live next to the hook config; discovery attaches them (hook targets).
  const inHookDir = (p: string) =>
    /(?:^|\/)\.(?:claude|cursor)\/hooks\//.test(p) ||
    ancestors(p).some((d) => (d === "hooks" ? pluginIndex.has("") : d.endsWith("/hooks") && pluginIndex.has(d.slice(0, -"/hooks".length))));
  // classifyFile only looks at the plugins that contain the file; pass those, in the order the tree lists them.
  const pluginRootsOf = (p: string) =>
    [...(pluginIndex.has("") ? [""] : []), ...ancestors(p).filter((d) => pluginIndex.has(d))]
      .sort((a, b) => pluginIndex.get(a)! - pluginIndex.get(b)!)
      .map((d) => (d === "" ? "/r" : abs(d)));

  // Agent files proper (SKILL.md, instructions, configs) come first, so a huge skill does not crowd them out.
  const isAgentFile = (p: string) => p === "SKILL.md" || p.endsWith("/SKILL.md") || !!classifyFile(abs(p), pluginRootsOf(p));

  let unportable = 0;
  const selected: { path: string; agent: boolean }[] = [];
  for (const p of paths) {
    const ext = p.includes(".") ? p.slice(p.lastIndexOf(".") + 1).toLowerCase() : "";
    if (BINARY_EXTENSIONS.has(ext)) continue;
    const agent = isAgentFile(p);
    if (!agent && !inSkill(p) && !inHookDir(p)) continue;
    if (options.portable && !isPortablePath(p)) {
      unportable++;
      continue;
    }
    selected.push({ path: p, agent });
  }
  // Stable: agent files first, each group in tree order.
  const ordered = [...selected.filter((s) => s.agent), ...selected.filter((s) => !s.agent)].map((s) => s.path);
  const files = ordered.slice(0, options.maxFiles);
  return { files, truncated: ordered.length - files.length, unportable };
}

/**
 * Of the scripts that hook commands name (repo-relative paths), the ones to fetch as well: present in the tree, not
 * selected yet and, when asked, portable. Binaries are kept, since SW017 reports binary hook targets.
 */
export function selectHookScripts(tree: string[], selected: string[], scripts: string[], options: { portable?: boolean } = {}): string[] {
  const inTree = new Set(tree);
  const have = new Set(selected);
  const out: string[] = [];
  for (const p of scripts) {
    if (!inTree.has(p) || have.has(p) || (options.portable && !isPortablePath(p))) continue;
    have.add(p);
    out.push(p);
  }
  return out;
}

/** A non-cone sparse-checkout pattern that matches exactly this file. */
export function sparsePattern(path: string): string {
  return "/" + path.replace(/[\\*?[\]!#]/g, (c) => "\\" + c).replace(/^ /, "\\ ").replace(/ $/, "\\ ");
}

// ---- Aggregation -------------------------------------------------------------------------------------------

export interface ReportFinding {
  ruleId: string;
  severity: Severity;
  confidence: string;
  file: string;
  line: number;
  message: string;
  snippet: string;
}

/** The subset of skillward's JSON report (format version 1) that the summary uses. */
export interface ScanReport {
  version: number;
  summary: { targets: number; files: number; findings: number };
  targets: { kind: string; path: string; files: string[] }[];
  findings: ReportFinding[];
  skipped: { path: string; reason: string }[];
  errors: { ruleId?: string; path: string; message: string }[];
}

export interface RepoReport {
  repo: string;
  sha: string;
  report: ScanReport;
}

type SeverityCounts = Record<Severity, number>;

export interface RuleStats {
  ruleId: string;
  findings: number;
  repos: number;
  files: number;
  bySeverity: SeverityCounts;
  byConfidence: Record<string, number>;
}

export interface Summary {
  repos: number;
  reposWithTargets: number;
  targets: number;
  targetsByKind: Record<string, number>;
  files: number;
  findings: number;
  bySeverity: SeverityCounts;
  /** Repos whose worst finding has this severity. */
  reposByWorstSeverity: SeverityCounts & { none: number };
  rules: RuleStats[];
  noisiestFiles: { repo: string; file: string; findings: number }[];
  errors: { repo: string; ruleId?: string; path: string; message: string }[];
  skipped: Record<string, number>;
}

const zeroSeverities = (): SeverityCounts => Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as SeverityCounts;
const worse = (a: Severity, b: Severity) => (SEVERITIES.indexOf(a) >= SEVERITIES.indexOf(b) ? a : b);

export function summarize(reports: RepoReport[], options: { noisiest?: number } = {}): Summary {
  const summary: Summary = {
    repos: reports.length,
    reposWithTargets: 0,
    targets: 0,
    targetsByKind: {},
    files: 0,
    findings: 0,
    bySeverity: zeroSeverities(),
    reposByWorstSeverity: { ...zeroSeverities(), none: 0 },
    rules: [],
    noisiestFiles: [],
    errors: [],
    skipped: {},
  };
  const rules = new Map<string, RuleStats & { repoSet: Set<string>; fileSet: Set<string> }>();
  const perFile = new Map<string, { repo: string; file: string; findings: number }>();

  for (const { repo, report } of reports) {
    if (report.targets.length) summary.reposWithTargets++;
    summary.targets += report.targets.length;
    summary.files += report.summary.files;
    for (const t of report.targets) summary.targetsByKind[t.kind] = (summary.targetsByKind[t.kind] ?? 0) + 1;
    for (const s of report.skipped) summary.skipped[s.reason] = (summary.skipped[s.reason] ?? 0) + 1;
    for (const e of report.errors) summary.errors.push({ repo, ...e });

    let worst: Severity | undefined;
    for (const f of report.findings) {
      summary.findings++;
      summary.bySeverity[f.severity]++;
      worst = worst ? worse(f.severity, worst) : f.severity;
      let stats = rules.get(f.ruleId);
      if (!stats) {
        stats = {
          ruleId: f.ruleId, findings: 0, repos: 0, files: 0, bySeverity: zeroSeverities(), byConfidence: {},
          repoSet: new Set(), fileSet: new Set(),
        };
        rules.set(f.ruleId, stats);
      }
      stats.findings++;
      stats.bySeverity[f.severity]++;
      stats.byConfidence[f.confidence] = (stats.byConfidence[f.confidence] ?? 0) + 1;
      stats.repoSet.add(repo);
      stats.fileSet.add(`${repo}:${f.file}`);
      const key = `${repo}:${f.file}`;
      const entry = perFile.get(key) ?? { repo, file: f.file, findings: 0 };
      entry.findings++;
      perFile.set(key, entry);
    }
    if (worst) summary.reposByWorstSeverity[worst]++;
    else summary.reposByWorstSeverity.none++;
  }

  summary.rules = [...rules.values()]
    .map(({ repoSet, fileSet, ...s }) => ({ ...s, repos: repoSet.size, files: fileSet.size }))
    .sort((a, b) => (a.ruleId < b.ruleId ? -1 : 1));
  summary.noisiestFiles = [...perFile.values()]
    .sort((a, b) => b.findings - a.findings || (a.repo + a.file < b.repo + b.file ? -1 : 1))
    .slice(0, options.noisiest ?? 20);
  return summary;
}

const pct = (n: number, total: number) => (total ? `${((100 * n) / total).toFixed(1)}%` : "—");
/** Table cells quote scanned content: keep them on one line and inert in Markdown. */
const cell = (s: string) => s.replace(/[\r\n]+/g, " ").replace(/\|/g, "\\|").replace(/`/g, "'");

export function renderSummary(summary: Summary, meta: { generatedAt: string; tool: string }): string {
  const lines: string[] = [];
  const sev = (c: SeverityCounts) => SEVERITIES.slice().reverse().map((s) => c[s]).join(" | ");
  lines.push(`# skillward corpus scan`, "", `Generated ${meta.generatedAt} with ${meta.tool}.`, "");
  lines.push(
    `- Repositories: ${summary.repos} (${summary.reposWithTargets} with agent files)`,
    `- Targets: ${summary.targets} (${Object.entries(summary.targetsByKind).map(([k, n]) => `${k} ${n}`).join(", ")})`,
    `- Files: ${summary.files}`,
    `- Findings: ${summary.findings} (high ${summary.bySeverity.high}, medium ${summary.bySeverity.medium}, low ${summary.bySeverity.low}, info ${summary.bySeverity.info})`,
    `- Rule errors: ${summary.errors.length}`,
    "",
  );
  const w = summary.reposByWorstSeverity;
  const base = summary.reposWithTargets;
  lines.push(
    "## Repositories by worst finding", "",
    "| worst | repos | share of repos with agent files |", "|---|---:|---:|",
    ...(["high", "medium", "low", "info"] as const).map((s) => `| ${s} | ${w[s]} | ${pct(w[s], base)} |`),
    `| none | ${w.none} | — |`, "",
  );
  lines.push(
    "## Rules", "",
    "| rule | findings | repos | files | high | medium | low | info |", "|---|---:|---:|---:|---:|---:|---:|---:|",
    ...summary.rules.map((r) => `| ${r.ruleId} | ${r.findings} | ${r.repos} | ${r.files} | ${sev(r.bySeverity)} |`), "",
  );
  if (summary.noisiestFiles.length) {
    lines.push(
      "## Noisiest files", "", "| repo | file | findings |", "|---|---|---:|",
      ...summary.noisiestFiles.map((f) => `| ${cell(f.repo)} | ${cell(f.file)} | ${f.findings} |`), "",
    );
  }
  if (summary.errors.length) {
    lines.push(
      "## Rule errors", "", "| repo | rule | file | message |", "|---|---|---|---|",
      ...summary.errors.map((e) => `| ${cell(e.repo)} | ${e.ruleId ?? ""} | ${cell(e.path)} | ${cell(e.message)} |`), "",
    );
  }
  return lines.join("\n");
}

/** Findings at or above `minSeverity`, grouped for manual review (the triage list). */
export function renderReview(reports: RepoReport[], minSeverity: Severity): string {
  const min = SEVERITIES.indexOf(minSeverity);
  const lines = [`# Findings to review (${minSeverity} and above)`, ""];
  for (const { repo, sha, report } of reports) {
    const findings = report.findings.filter((f) => SEVERITIES.indexOf(f.severity) >= min);
    if (!findings.length) continue;
    lines.push(`## ${repo} @ ${sha.slice(0, 12)}`, "");
    for (const f of findings) {
      lines.push(
        `- **${f.ruleId}** ${f.severity}/${f.confidence} \`${cell(f.file)}:${f.line}\` — ${cell(f.message)}`,
        `  - snippet: \`${cell(f.snippet)}\``,
      );
    }
    lines.push("");
  }
  return lines.join("\n");
}

// ---- Precision sampling --------------------------------------------------------------------------------------

/** `n` distinct indices from `[0, total)`, uniformly at random and reproducible for a given seed, in sorted order. */
export function sampleIndices(total: number, n: number, seed: number): number[] {
  let state = seed >>> 0 || 1;
  // mulberry32
  const next = () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let x = state;
    x = Math.imul(x ^ (x >>> 15), x | 1);
    x ^= x + Math.imul(x ^ (x >>> 7), x | 61);
    return ((x ^ (x >>> 14)) >>> 0) / 4294967296;
  };
  const picked = new Map<number, number>(); // partial Fisher–Yates over a virtual array
  const out: number[] = [];
  for (let i = 0; i < Math.min(n, total); i++) {
    const j = i + Math.floor(next() * (total - i));
    out.push(picked.get(j) ?? j);
    picked.set(j, picked.get(i) ?? i);
  }
  return out.sort((a, b) => a - b);
}

/** Wilson score interval for `k` successes out of `n` (95 % by default). */
export function wilson(k: number, n: number, z = 1.96): { p: number; low: number; high: number } {
  if (n === 0) return { p: 0, low: 0, high: 0 };
  const p = k / n;
  const denom = 1 + (z * z) / n;
  const center = (p + (z * z) / (2 * n)) / denom;
  const half = (z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n))) / denom;
  return { p, low: Math.max(0, center - half), high: Math.min(1, center + half) };
}

/** Cohen's κ for two raters' labels of the same items: agreement beyond what their label frequencies give by chance. */
export function cohenKappa<T>(pairs: [T, T][]): { agreement: number; kappa: number } {
  const n = pairs.length;
  if (n === 0) return { agreement: 0, kappa: 0 };
  const po = pairs.filter(([a, b]) => a === b).length / n;
  const labels = new Set(pairs.flat());
  let pe = 0;
  for (const l of labels) pe += (pairs.filter(([a]) => a === l).length / n) * (pairs.filter(([, b]) => b === l).length / n);
  // Both raters used one and the same label for everything: agreement is total, chance agreement too.
  return { agreement: po, kappa: pe === 1 ? 1 : (po - pe) / (1 - pe) };
}

/** Lines `line ± radius` (1-based) of `text`, each cut to `width` characters. */
export function contextLines(text: string, line: number, radius: number, width = 200): { n: number; text: string }[] {
  const lines = text.split(/\r?\n/);
  const from = Math.max(1, line - radius);
  const to = Math.min(lines.length, line + radius);
  const out: { n: number; text: string }[] = [];
  for (let n = from; n <= to; n++) {
    const l = lines[n - 1]!;
    out.push({ n, text: l.length > width ? `${l.slice(0, width)}…` : l });
  }
  return out;
}

/** Runs `fn` over `items` with at most `limit` in flight. */
export async function pool<T>(items: T[], limit: number, fn: (item: T, index: number) => Promise<void>): Promise<void> {
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      await fn(items[i]!, i);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
}
