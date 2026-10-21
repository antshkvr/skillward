import { createColors } from "picocolors";
import { CAPABILITIES, type TargetCapabilities } from "../capabilities/index.js";
import { escapeInvisible } from "../text.js";
import { configJson, type ConfigInfo } from "./config-note.js";
import type { Severity } from "../types.js";
import { VERSION } from "../version.js";

/** Version of the `explain --format json` output. Bump on breaking changes; adding fields is not breaking. */
export const EXPLAIN_REPORT_VERSION = 1;

/** Short names for the "not seen" line. */
const SHORT: Record<string, string> = {
  "remote-code": "remote code",
  "remote-control": "remote control",
  approvals: "approvals off",
  secrets: "secrets",
  network: "network",
  persistence: "persistence",
  destructive: "destructive",
  concealment: "concealment",
  autorun: "autorun",
};

export function explainText(
  root: string,
  targets: TargetCapabilities[],
  options: { color: boolean; all: boolean; notes?: string[] },
): string {
  const c = createColors(options.color);
  const paint: Record<Severity, (s: string) => string> = {
    high: (s) => c.bold(c.red(s)),
    medium: c.yellow,
    low: c.cyan,
    info: c.dim,
  };
  const out: string[] = [];
  const notable = targets.filter((t) => t.capabilities.length > 0);
  const shown = options.all ? targets : notable;
  const width = Math.max(...CAPABILITIES.map((cap) => cap.label.length));

  for (const t of shown) {
    const scripts = t.scripts ? ` · ${t.scripts} script${t.scripts === 1 ? "" : "s"}` : "";
    out.push(`${c.underline(escapeInvisible(t.path))}  ${c.dim(`${t.kind} · ${t.files} file${t.files === 1 ? "" : "s"}${scripts}`)}`);
    if (!t.capabilities.length) {
      out.push(c.green("  nothing notable"), "");
      continue;
    }
    for (const cap of t.capabilities) {
      const where = cap.locations.map((l) => escapeInvisible(placeIn(t.path, l.file, l.line))).join(" · ");
      const more = cap.places > cap.locations.length ? c.dim(` (+${cap.places - cap.locations.length} more)`) : "";
      out.push(`  ${paint[cap.severity](cap.severity.toUpperCase().padEnd(7))} ${cap.label.padEnd(width)}  ${c.dim(where)}${more}`);
    }
    const seen = new Set(t.capabilities.map((cap) => cap.id));
    const missing = CAPABILITIES.filter((cap) => !seen.has(cap.id)).map((cap) => SHORT[cap.id]);
    if (missing.length) out.push(c.dim(`  not seen: ${missing.join(", ")}`));
    out.push("");
  }

  const quiet = targets.length - notable.length;
  if (!options.all && quiet > 0) out.push(c.dim(`${quiet} more target(s) with nothing notable (--all lists them).`), "");

  if (options.notes?.length) out.push(...options.notes, "");
  if (!targets.length) {
    out.push(`No agent configuration found under ${escapeInvisible(root)}.`);
    return out.join("\n") + "\n";
  }
  const totals = CAPABILITIES.map((cap) => [cap, targets.filter((t) => t.capabilities.some((x) => x.id === cap.id)).length] as const).filter(
    ([, n]) => n > 0,
  );
  out.push(
    totals.length
      ? `${targets.length} target(s) — ${totals.map(([cap, n]) => `${cap.label}: ${n}`).join(" · ")}`
      : c.green(`✔ Nothing notable in ${targets.length} target(s).`),
  );
  out.push(c.dim("This is a summary of `skillward scan` findings; run scan for details and exit codes."));
  return out.join("\n") + "\n";
}

/** A finding's place relative to its target: `line 6` for single-file targets, `scripts/x.sh:3` inside a skill. */
function placeIn(target: string, file: string, line: number): string {
  if (file === target) return `line ${line}`;
  if (target !== "." && file.startsWith(target + "/")) return `${file.slice(target.length + 1)}:${line}`;
  return `${file}:${line}`;
}

export function explainJson(root: string, targets: TargetCapabilities[], config?: ConfigInfo): string {
  const tool = { name: "skillward", version: VERSION };
  const report = { version: EXPLAIN_REPORT_VERSION, tool, root, ...(config ? { config: configJson(config) } : {}), targets };
  return JSON.stringify(report, null, 2) + "\n";
}
