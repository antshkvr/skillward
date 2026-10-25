import { createColors } from "picocolors";
import { meetsThreshold } from "../engine/index.js";
import { escapeInvisible } from "../text.js";
import { configNotes } from "./config-note.js";
import { SEVERITIES, type Finding, type Severity } from "../types.js";
import type { Reporter } from "./types.js";

/** Splits `text` at spaces into lines of at most `width` characters; a longer word gets a line of its own. */
export function wrapWords(text: string, width: number): string[] {
  const lines: string[] = [];
  let line = "";
  for (const word of text.split(" ")) {
    if (line && line.length + 1 + word.length > width) {
      lines.push(line);
      line = word;
    } else {
      line = line ? `${line} ${word}` : word;
    }
  }
  lines.push(line);
  return lines;
}

export const textReporter: Reporter = ({ result, failOn, color, config, width }) => {
  const c = createColors(color);
  const paint: Record<Severity, (s: string) => string> = {
    high: (s) => c.bold(c.red(s)),
    medium: c.yellow,
    low: c.cyan,
    info: c.dim,
  };
  const out: string[] = [];

  const byFile = new Map<string, Finding[]>();
  for (const f of result.findings) {
    const list = byFile.get(f.file);
    if (list) list.push(f);
    else byFile.set(f.file, [f]);
  }

  for (const [file, findings] of byFile) {
    out.push(c.underline(escapeInvisible(file)));
    for (const f of findings) {
      const pos = `${f.line}:${f.column ?? 1}`.padEnd(8);
      const sev = paint[f.severity](f.severity.padEnd(6));
      const rule = c.dim(`${f.ruleId}`);
      const conf = f.confidence === "high" ? "" : ` (confidence: ${f.confidence})`;
      const message = escapeInvisible(f.message);
      const indent = 2 + pos.length + 7 + f.ruleId.length + 2;
      // In a terminal, wrap at spaces under the message instead of letting the terminal cut words in half.
      const room = width ? width - 1 - indent : 0;
      if (room >= 40 && message.length + conf.length > room) {
        const lines = wrapWords(message, room);
        const last = lines.length - 1;
        if (conf && lines[last]!.length + conf.length <= room) lines[last] += c.dim(conf);
        else if (conf) lines.push(c.dim(conf.trimStart()));
        out.push(`  ${pos}${sev} ${rule}  ${lines[0]}`, ...lines.slice(1).map((l) => " ".repeat(indent) + l));
      } else {
        out.push(`  ${pos}${sev} ${rule}  ${message}${conf && c.dim(conf)}`);
      }
      if (f.snippet) out.push(`  ${" ".repeat(8)}${c.dim("│ " + f.snippet)}`);
    }
    out.push("");
  }

  if (result.suppressed.length) {
    // Shown on purpose: a malicious skill can add skillward-ignore comments too.
    out.push(c.yellow(`${result.suppressed.length} finding(s) suppressed by inline skillward-ignore:`));
    for (const f of result.suppressed) {
      const reason = f.suppression.reason ? escapeInvisible(f.suppression.reason) : "no reason given";
      out.push(c.dim(`  ${escapeInvisible(f.file)}:${f.line}  ${f.ruleId} ${f.severity}  (${reason}; directive on line ${f.suppression.line})`));
    }
    out.push("");
  }
  if (result.baseline) {
    const { findings: known, stale } = result.baseline;
    if (known.length) out.push(c.dim(`${known.length} known finding(s) from the baseline not shown (run without --baseline to see them).`));
    if (stale) out.push(c.dim(`${stale} baseline entr${stale === 1 ? "y" : "ies"} no longer match: fixed or changed. Refresh it with --write-baseline.`));
    if (known.length || stale) out.push("");
  }
  const notes = configNotes(config, result.root, color);
  if (notes.length) out.push(...notes, "");
  for (const s of result.skipped) out.push(c.dim(`skipped ${escapeInvisible(s.path)}: ${s.reason}`));
  for (const e of result.errors) {
    out.push(c.red(`error ${e.ruleId ? `in ${e.ruleId} ` : ""}on ${escapeInvisible(e.path)}: ${e.message}`));
  }
  if (result.skipped.length || result.errors.length) out.push("");

  const files = result.targets.reduce((n, t) => n + t.files.length, 0);
  const scanned = `${result.targets.length} target(s), ${files} file(s) scanned`;
  if (result.targets.length === 0) {
    // Not a green check: nothing was checked. Usually the wrong folder, or a project without agent configuration.
    out.push(
      c.yellow(`No agent configuration found under ${escapeInvisible(result.root)}.`),
      c.dim(
        "Looked for skills (folders with SKILL.md), CLAUDE.md / AGENTS.md / GEMINI.md, .claude/, .mcp.json, plugins, and Cursor, Copilot, Windsurf, Cline and Kiro rules. Use --global to include your user-level configuration (~/.claude, ~/.cursor, ~/.gemini, …).",
      ),
    );
  } else if (result.findings.length === 0) {
    out.push(c.green(`✔ No ${result.baseline ? "new " : ""}findings. ${scanned}.`));
  } else {
    const counts = [...SEVERITIES]
      .reverse()
      .map((s) => [s, result.findings.filter((f) => f.severity === s).length] as const)
      .filter(([, n]) => n > 0)
      .map(([s, n]) => paint[s](`${n} ${s}`))
      .join(", ");
    const failing = result.findings.filter((f) => meetsThreshold(f.severity, failOn)).length;
    const verdict = failing > 0 ? c.red(`✖ ${failing} at or above --fail-on ${failOn}`) : c.green(`below --fail-on ${failOn}`);
    out.push(`${result.findings.length} ${result.baseline ? "new " : ""}finding(s): ${counts}. ${scanned}. ${verdict}.`);
  }
  return out.join("\n") + "\n";
};
