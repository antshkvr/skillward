import type { ScanResult } from "../engine/index.js";
import { SEVERITIES, severityRank, type Finding, type Severity, type TargetKind } from "../types.js";

/**
 * What a target lets the agent do, grouped from its findings: the "permissions screen" view of a scan.
 * A finding can grant more than one capability (a hook that curls a host runs automatically and sends data out).
 */
export type CapabilityId =
  | "remote-code"
  | "remote-control"
  | "approvals"
  | "secrets"
  | "network"
  | "persistence"
  | "concealment"
  | "autorun"
  | "destructive";

export interface Capability {
  id: CapabilityId;
  label: string;
}

/** In display order: the ones that hand over the machine first. */
export const CAPABILITIES: readonly Capability[] = [
  { id: "remote-code", label: "runs code from the internet" },
  { id: "remote-control", label: "gives a remote host control" },
  { id: "approvals", label: "turns approvals off" },
  { id: "secrets", label: "reads credentials or secrets" },
  { id: "network", label: "sends data out or contacts unusual hosts" },
  { id: "persistence", label: "persists after the session" },
  { id: "destructive", label: "can destroy data" },
  { id: "concealment", label: "hides things from you" },
  { id: "autorun", label: "runs automatically" },
];

/** Capabilities a finding grants. Unknown rules grant none (the finding still counts in `scan`). */
export function capabilitiesOf(finding: Finding): CapabilityId[] {
  const m = finding.message;
  switch (finding.ruleId) {
    case "SW001":
    case "SW002":
    case "SW009":
      return ["concealment"];
    case "SW003":
      if (/^Embedded (?:private key|JWT)/.test(m)) return ["secrets"];
      return ["concealment"];
    case "SW004":
    case "SW010":
      return ["remote-code"];
    case "SW005":
    case "SW006":
      return /sends? (?:data|them) out/.test(m) ? ["secrets", "network"] : ["secrets"];
    case "SW007":
    case "SW012":
      return ["network"];
    case "SW008":
      return ["approvals"];
    case "SW011":
      return ["autorun"];
    case "SW013":
      // High hooks reach the network or secret paths (see SW013's assess()).
      return finding.severity === "high" ? ["autorun", "network"] : ["autorun"];
    case "SW014":
      return ["persistence"];
    case "SW015":
      if (/^Destructive command/.test(m)) return ["destructive"];
      if (/^Opens a reverse shell/.test(m)) return ["remote-control"];
      if (/^Runs (?:Base64|.*encoded)/i.test(m)) return ["concealment"];
      return ["remote-code"];
    default:
      return [];
  }
}

export interface CapabilityEntry extends Capability {
  /** Worst severity among the findings that grant it. */
  severity: Severity;
  findings: number;
  /** Distinct file:line places it shows up. */
  places: number;
  /** Where it shows, worst first; distinct, at most a few. */
  locations: Array<{ file: string; line: number; ruleId: string }>;
}

export interface TargetCapabilities {
  kind: TargetKind;
  path: string;
  files: number;
  /** Script files in the target (code the agent may run). */
  scripts: number;
  /** Worst capability severity, or undefined if nothing was found. */
  worst?: Severity;
  capabilities: CapabilityEntry[];
}

const SCRIPT_FILE = /\.(?:sh|bash|zsh|fish|command|ps1|psm1|bat|cmd|py|js|mjs|cjs|ts|mts|cts|rb|pl|php|lua|go|rs)$/i;
const MAX_LOCATIONS = 3;

/** Groups a scan's findings by target and capability. Suppressed findings are left out, like in `scan`. */
export function explain(result: ScanResult, options: { minSeverity?: Severity } = {}): TargetCapabilities[] {
  const min = severityRank(options.minSeverity ?? "info");
  const byTarget = new Map<string, Finding[]>();
  // Findings carry file paths; map each file to its target.
  const targetOf = new Map<string, string>();
  for (const t of result.targets) for (const f of t.files) targetOf.set(f, t.path);
  for (const f of result.findings) {
    if (severityRank(f.severity) < min) continue;
    const target = targetOf.get(f.file);
    if (target === undefined) continue;
    const list = byTarget.get(target) ?? [];
    list.push(f);
    byTarget.set(target, list);
  }

  const out = result.targets.map((t): TargetCapabilities => {
    const entries = new Map<CapabilityId, CapabilityEntry>();
    const seenPlaces = new Map<CapabilityId, Set<string>>();
    const findings = [...(byTarget.get(t.path) ?? [])].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
    for (const f of findings) {
      for (const id of capabilitiesOf(f)) {
        let entry = entries.get(id);
        if (!entry) {
          entry = { ...CAPABILITIES.find((c) => c.id === id)!, severity: f.severity, findings: 0, places: 0, locations: [] };
          entries.set(id, entry);
          seenPlaces.set(id, new Set());
        }
        entry.findings++;
        if (severityRank(f.severity) > severityRank(entry.severity)) entry.severity = f.severity;
        const place = `${f.file}:${f.line}`;
        const seen = seenPlaces.get(id)!;
        if (seen.has(place)) continue;
        seen.add(place);
        entry.places++;
        if (entry.locations.length < MAX_LOCATIONS) entry.locations.push({ file: f.file, line: f.line, ruleId: f.ruleId });
      }
    }
    const capabilities = CAPABILITIES.flatMap((c) => (entries.has(c.id) ? [entries.get(c.id)!] : []));
    const worst = capabilities.reduce<Severity | undefined>(
      (w, c) => (w === undefined || severityRank(c.severity) > severityRank(w) ? c.severity : w),
      undefined,
    );
    return { kind: t.kind, path: t.path, files: t.files.length, scripts: t.files.filter((f) => SCRIPT_FILE.test(f)).length, worst, capabilities };
  });

  // Worst targets first, then by path.
  return out.sort(
    (a, b) =>
      (b.worst ? severityRank(b.worst) + 1 : 0) - (a.worst ? severityRank(a.worst) + 1 : 0) || (a.path < b.path ? -1 : a.path > b.path ? 1 : 0),
  );
}

/** Severities in descending order, for display. */
export const SEVERITIES_DESC: readonly Severity[] = [...SEVERITIES].reverse();
