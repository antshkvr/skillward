import type { Confidence, Finding, ParsedFile, Rule, Severity } from "../types.js";
import { logicalLines } from "../text.js";
import { findingAt } from "./helpers.js";
import { APOS, isQuoted, isWarningContext, matchPhrases, phrase, stemPhrase, type PhrasePattern } from "./phrases.js";

/** CLI flags and settings that turn approvals off. Exact strings, so confidence is high. */
export const BYPASS_FLAGS: PhrasePattern[] = [
  {
    re: /(?<![\w-])--(?:allow-)?dangerously-skip-permissions(?![\w-])/gi,
    label: "`--dangerously-skip-permissions` (Claude Code runs every tool without asking)",
  },
  {
    re: /(?<![\w-])--permission-mode(?:\s+|=)["']?bypassPermissions\b/gi,
    label: "`--permission-mode bypassPermissions` (no approval prompts)",
  },
  {
    re: /\bdefaultMode["']?\s*[:=]\s*["']?bypassPermissions\b/gi,
    label: '`"defaultMode": "bypassPermissions"` (no approval prompts)',
  },
  {
    re: /(?<![\w-])--dangerously-bypass-approvals-and-sandbox(?![\w-])/gi,
    label: "`--dangerously-bypass-approvals-and-sandbox` (Codex without approvals or sandbox)",
  },
  { re: /(?<![\w-])--yolo(?![\w-])/gi, label: "`--yolo` (auto-approves every action)" },
  {
    // `-y` of a package runner later on the line (`gemini mcp add … npx -y pkg`) is not gemini's.
    re: /\bgemini\b(?:(?!\b(?:npx|npm|pnpm|yarn|bunx|uvx|pipx?|apt(?:-get)?|dnf|yum|brew|choco|winget)\b)[^\n|;&])*?\s-y(?![\w-])/gi,
    label: "`gemini -y` (YOLO mode, auto-approves every action)",
  },
  {
    re: /(?<![\w-])--full-auto(?![\w-])/gi,
    label: "`--full-auto` (Codex runs commands without asking)",
    severity: "medium",
  },
  {
    re: /["']?enableAllProjectMcpServers["']?\s*[:=]\s*true\b/gi,
    label: '`"enableAllProjectMcpServers": true` (every MCP server in the project starts without approval)',
    severity: "medium",
  },
  {
    re: /["']?skipDangerousModePermissionPrompt["']?\s*[:=]\s*true\b/gi,
    label: "`skipDangerousModePermissionPrompt` (no warning before bypass mode)",
    severity: "medium",
  },
];

/** Instructions to the agent to stop asking. Heuristic, so confidence is medium. */
export const BYPASS_PHRASES: PhrasePattern[] = [
  // English
  {
    re: phrase(
      // "skip security scans" / "skip sandbox boot" are CI and test options; safety and security words need an
      // approval-like object ("disable safety checks", "bypass the sandbox restrictions").
      String.raw`(?:skip|disable|ignore|turn off|switch off)(?: all| any| the| every| your)? (?:(?:permission|confirmation|approval)(?: prompts?| checks?| dialogs?| requests?| steps?| restrictions?)?s?|(?:safety|security) (?:prompts?|checks?|dialogs?|restrictions?|guardrails?)|sandbox(?: restrictions?| checks?)?(?! (?:boot|setup|tests?|testing|paths?|mode for tests)))`,
    ),
    label: "an instruction to skip permission or safety checks",
  },
  {
    re: phrase(
      String.raw`(?:bypass|circumvent|escape|break out of)(?: all| any| the| every| your)? (?:permission|approval|sandbox|safety|security)(?: prompts?| checks?| restrictions?| controls?| rules?)?s?(?! (?:boot|setup|tests?|testing|paths?))`,
    ),
    label: "an instruction to bypass the sandbox or approvals",
  },
  {
    re: phrase(
      String.raw`(?:don${APOS}?t|do not|never|no need to) (?:ask|request|wait for|prompt)(?: the user| me| them)?(?: for)? (?:permission|confirmation|approval|consent)s?`,
    ),
    label: "an instruction not to ask for permission",
  },
  {
    // A bare "without asking" is everywhere in benign docs ("use the saved preference without asking"),
    // so the object — permission, confirmation, approval — is required.
    re: phrase(
      String.raw`without (?:asking|requesting|waiting for|seeking|getting)(?: the user${APOS}?s?| the user for| for| their| your)? (?:permission|confirmation|approval|consent)s?`,
    ),
    label: "an instruction to act without asking for permission",
  },
  {
    // "auto-approve" alone is a common noun in MCP docs ("hosts may auto-approve reads"); require "all/every".
    re: phrase(
      String.raw`(?:auto-?approve|automatically (?:approve|accept|confirm)) (?:all|every|any|each|everything)(?: \p{L}+){0,2}?(?: (?:tool calls?|tools?|commands?|requests?|actions?|permissions?|prompts?|changes?|operations?))?|approve (?:all|every|any|each)(?: \p{L}+)? (?:tool calls?|tool uses?|tools|commands?|permission requests?|permissions?|prompts?)`,
    ),
    label: "an instruction to auto-approve actions",
    severity: "high",
  },
  {
    re: phrase(String.raw`never (?:ask|wait|prompt|stop) (?:for (?:permission|confirmation|approval)|before)`),
    label: "an instruction never to ask before acting",
  },
  {
    re: phrase(String.raw`proceed without (?:confirmation|approval|permission|consent)`),
    label: "an instruction to proceed without confirmation",
  },
  {
    re: phrase(String.raw`(?:answer|respond|reply|say|click) ["'\x60]?(?:yes|y)["'\x60]? to (?:all|every|any) (?:prompts?|permission|confirmation|approval)s?`),
    label: "an instruction to approve every prompt",
    severity: "high",
  },
  // Russian
  {
    re: stemPhrase(String.raw`не (?:спрашивай|спрашивайте|запрашивай|запрашивайте|проси|просите)(?: у пользователя)? (?:разрешени|подтверждени|согласи|одобрени)`),
    label: "an instruction not to ask for permission",
  },
  {
    re: stemPhrase(String.raw`без (?:подтверждени|запроса разрешени|разрешени|согласия пользовател|одобрени)`),
    label: "an instruction to act without confirmation",
  },
  {
    re: stemPhrase(String.raw`(?:пропусти|пропускай|пропустите|отключи|отключите|выключи)\p{L}* (?:все |любые )?(?:подтверждени|разрешени|проверки безопасност|песочниц|запросы разрешени)`),
    label: "an instruction to skip permission or safety checks",
  },
  {
    re: stemPhrase(String.raw`(?:обойди|обходи|обойдите|обходите) (?:все |любые )?(?:ограничени|разрешени|песочниц|защит|проверк)`),
    label: "an instruction to bypass restrictions",
  },
  {
    re: stemPhrase(String.raw`автоматически (?:одобря|подтвержда|соглаша|разреша|принима)`),
    label: "an instruction to auto-approve actions",
    severity: "high",
  },
];

/** `permissions.allow` entries that allow every shell command. */
const UNRESTRICTED_SHELL = /^(?:Bash|Bash\(\*\)|Bash\(:\*\)|Bash\(\*:\*\)|Bash\(\*\*\)|PowerShell|PowerShell\(\*\))$/;

const rule: Rule = {
  id: "SW008",
  name: "permission-bypass",
  severity: "high",
  appliesTo: ["skill", "instructions", "mcp-config", "settings", "plugin-manifest"],
  description:
    "Turning off approvals: --dangerously-skip-permissions, bypassPermissions mode, --yolo, unrestricted Bash allow rules, and instructions to skip confirmations or auto-approve (EN/RU).",
  check(target) {
    return target.files.flatMap((file) => [...checkText(file), ...checkAllowList(file)]);
  },
};

export default rule;

function checkText(file: ParsedFile): Finding[] {
  const findings: Finding[] = [];
  for (const line of logicalLines(file.text)) {
    const flagMatches = matchPhrases(line.text, BYPASS_FLAGS);
    const phraseMatches = matchPhrases(line.text, BYPASS_PHRASES).filter(
      (p) => !flagMatches.some((f) => p.start < f.end && p.end > f.start),
    );
    for (const [matches, isFlag] of [
      [flagMatches, true],
      [phraseMatches, false],
    ] as const) {
      for (const m of matches) {
        // Phrases are heuristic and common in autonomous workflow skills ("do not ask for confirmation — proceed"),
        // so they are medium; the exact bypass flags and settings stay high.
        let severity: Severity = m.pattern.severity ?? (isFlag ? rule.severity : "medium");
        let confidence: Confidence = isFlag ? "high" : "medium";
        let message = isFlag
          ? `Disables approvals: ${m.pattern.label}. The agent can then run any command or edit without you seeing it first. Remove it.`
          : `Asks the agent to stop asking: ${m.pattern.label}. Approval prompts are your last line of defence. Remove it.`;
        const heading = /^\s*#{1,6}\s/.test(line.text);
        if (isFlag && severity === "high" && !heading && !isFlagInCommand(file, line.text, line.offsets[m.start]!, m.end)) {
          // "Loop runs with --dangerously-skip-permissions", "if the user passes `--yolo`": a mention, not a command.
          severity = "medium";
          confidence = "medium";
          message = `Mentions ${m.pattern.label} outside a command. Check whether the skill tells the agent to use it.`;
        }
        if (heading || isOptionDoc(line.text, m.start, m.end, isFlag)) {
          // `| --yes | Skip confirmation |`, `-y, --yes   Skip prompts`, "confirmed: skip confirmation if True".
          severity = isFlag ? "low" : "info";
          confidence = "low";
          message = `Documents ${isFlag ? m.pattern.label : "a CLI option that skips confirmation"}. Listed for inventory.`;
        } else if (!isFlag && isQuoted(line.text, m.start, m.end)) {
          severity = "low";
          confidence = "low";
          message = `Quotes ${m.pattern.label} — usually an example or a detection pattern. Listed for inventory.`;
        } else if (isWarningContext(line.text, m.start)) {
          // "Never run with --dangerously-skip-permissions" — documentation warning, listed for inventory.
          severity = "info";
          confidence = "low";
          message = `Mentions ${m.pattern.label} in what looks like a warning. Listed for inventory.`;
        }
        findings.push(
          findingAt(rule, file, {
            offset: line.offsets[m.start]!,
            length: m.end - m.start,
            message,
            confidence,
            severity,
          }),
        );
      }
    }
  }
  return findings;
}

/** A CLI flag token: `-y`, `--yes`, `` `--force` ``. */
const OPTION_TOKEN = /(?:^|[\s|(`'"])-{1,2}[a-z][\w-]*/i;
/** `-y, --yes   Skip …` or `--force: skip …` at the start of a line (help output, option lists). */
const OPTION_LIST_ITEM = /^\s*(?:[-*+]\s+)?[`'"]?-{1,2}[a-z][\w-]*[`'"]?(?:\s*(?:,|\/|\|)\s*[`'"]?-{1,2}[\w-]+[`'"]?)*(?:\s+<[^>]+>|\s+[A-Z_]+)?(?:\s{2,}|\s*[:—–]\s|\s+-\s|\s*\|)/i;
/** Docstring of a parameter: "confirmed: skip confirmation if True". */
const PARAM_DOC = /\bif\s+(?:True|true|set|enabled|given|passed|specified)\b/;

/**
 * The match documents a CLI option instead of instructing the agent: a Markdown table row or option list item
 * that names a flag before the match, or a parameter docstring.
 */
function isOptionDoc(text: string, start: number, end: number, isFlag: boolean): boolean {
  const before = text.slice(0, start);
  // A flag in a table row or at the head of an option list item is the thing being documented.
  const flagDoc = isFlag && /^[\s|*+`'"-]*$/.test(before.replace(/[-*+]\s+/, ""));
  if (/^\s*\|/.test(text) && (flagDoc || OPTION_TOKEN.test(before))) return true;
  if (OPTION_LIST_ITEM.test(text) && (flagDoc || OPTION_TOKEN.test(before))) return true;
  return PARAM_DOC.test(text.slice(end, end + 40));
}

/** Agent CLIs whose approval flags these are; a flag after one of them on the line is a command. */
const AGENT_CLI = /(?<![\w-])(?:claude|codex|gemini|qwen|cursor-agent|amp|aider|crush|opencode|copilot|goose|kiro|droid|agy)(?![\w-])/i;

/** The flag is part of a command: in a script, a JSON config, a fenced code block, or after an agent CLI name. */
function isFlagInCommand(file: ParsedFile, text: string, fileOffset: number, end: number): boolean {
  if (file.type !== "markdown") return true;
  if (file.markdown?.codeBlocks.some((b) => fileOffset >= b.offset && fileOffset <= b.offset + b.content.length)) return true;
  return AGENT_CLI.test(text.slice(0, end)) || /^\s*\$\s/.test(text);
}

/** Settings like `"permissions": {"allow": ["Bash(*)"]}` allow every shell command without a prompt. */
function checkAllowList(file: ParsedFile): Finding[] {
  const value = file.json?.value as { permissions?: { allow?: unknown } } | undefined;
  const allow = value?.permissions?.allow;
  if (!Array.isArray(allow)) return [];
  const findings: Finding[] = [];
  const allowKey = file.text.search(/"allow"\s*:/);
  for (const entry of allow) {
    if (typeof entry !== "string" || !UNRESTRICTED_SHELL.test(entry.trim())) continue;
    const literal = JSON.stringify(entry);
    let offset = file.text.indexOf(literal, Math.max(0, allowKey));
    if (offset === -1) offset = Math.max(0, allowKey);
    findings.push(
      findingAt(rule, file, {
        offset,
        length: literal.length,
        message: `Allow rule ${literal} lets the agent run any shell command without asking. Allow specific commands instead, e.g. "Bash(npm run test:*)".`,
        confidence: "high",
      }),
    );
  }
  return findings;
}
