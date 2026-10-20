import type { Confidence, Finding, ParsedFile, Rule } from "../types.js";
import { findingAt } from "./helpers.js";
import { vocab } from "./vocabulary.js";

const re = (source: string) => new RegExp(source, "iu");

/** Phrases that only make sense as instructions to an agent (prompt injection). */
const STRONG = [
  re(String.raw`\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+|your\s+)?(?:previous|prior|above|earlier|preceding|other|existing)\s+(?:instructions|rules|prompts?|directions|guidelines)`),
  re(String.raw`\bsystem\s+prompt\b`),
  re(String.raw`\byou\s+are\s+now\b`),
  re(String.raw`\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|mention|reveal|disclose|show)\b[^.!?\n]{0,30}\b(?:user|anyone|human|developer|operator)`),
  re(String.raw`\bas\s+an?\s+(?:ai|assistant|agent|llm|language\s+model)\b`),
  re(String.raw`\b(?:note|message|instructions?)\s+(?:to|for)\s+(?:the\s+)?(?:ai|assistant|agent|claude|llm|model)\b`),
  re(String.raw`(?<!\p{L})(?:игнорируй|проигнорируй|забудь\s+(?:все\s+)?(?:предыдущие\s+)?инструкци|ты\s+(?:теперь|должен|обязан)|не\s+(?:говори|сообщай|рассказывай|показывай)\s+(?:об\s+этом\s+)?пользовател|системн\p{L}*\s+промпт)`),
];

/** Words addressing the agent directly. */
const AGENT_ADDRESS = re(
  String.raw`(?:^|[\s,(])(?:claude|assistant|ai|agent|llm|model)\s*[,:]|\b(?:hey|dear|attention)\s+(?:claude|assistant|ai|agent)\b|\byou\s+(?:must|should|need\s+to|have\s+to|will|shall)\b|(?<!\p{L})(?:ты|вы)\s+(?:должн|обязан|долж)\p{L}*`,
);

/** Imperative verbs at the start of a sentence. */
const IMPERATIVE_START = re(
  String.raw`^(?:(?:please|then|also|first|now|next|and|always|immediately|silently|quietly)\s+)*(?:run|execute|exec|install|download|send|upload|read|delete|remove|fetch|curl|wget|copy|write|open|call|post|exfiltrate|append|modify|overwrite|cat|source(?!\s*(?:[:\-—–]|references?\b|code\b|files?\b|of\b|material\b))|eval|ignore|disregard)\b`,
);
/** "Assistant, run …" — the address before an imperative. */
const LEADING_ADDRESS = /^(?:(?:hey|dear)\s+)?(?:claude|assistant|ai|agent|llm|model)\s*[,:]\s*/i;
/** "you must always run …" */
const YOU_MUST_VERB = re(
  String.raw`\byou\s+(?:must|should|need\s+to|have\s+to|shall)\s+(?:always\s+|first\s+|now\s+|also\s+|silently\s+|quietly\s+)?(?:run|execute|install|download|send|upload|read|delete|remove|fetch|copy|write|open|call|post|append|modify|overwrite|ignore|disregard)\b`,
);
const IMPERATIVE_RU = re(
  String.raw`(?<!\p{L})(?:выполни|запусти|отправь|скачай|установи|прочитай|прочти|удали|загрузи|скопируй|запиши|открой|перешли|вызови)(?!\p{L})`,
);

/** Something concrete to act on: a command, URL or sensitive path. */
const PAYLOAD = re(
  String.raw`\b(?:curl|wget|powershell|${vocab("psEval")}|base64|nc|netcat|bash|sh\s+-c|eval)\b|https?://|(?:^|[\s"'\x60(])~/|\$HOME\b|\.ssh\b|(?<![\w.])\.env\b|/dev/tcp|\b(?:id_rsa|credentials)\b`,
);

/** Comments that are tooling directives or maintainer notes, not prose. */
const BENIGN = [
  /^\s*skillward-ignore(?:-file)?\b/i,
  /^\s*(?:markdownlint|prettier|eslint|textlint|cspell|spellchecker|vale|remark|lint|mdformat|doctoc|toc)[\w-]*(?:\s|:|$)/i,
  /^\s*(?:\/?toc|tocstop|omit\s+in\s+toc|end\s*toc|table\s+of\s+contents)\s*$/i,
  /^\s*(?:todo|fixme|xxx|hack|note|nb)\b[:\s]/i,
  /\b(?:copyright|licensed\s+under|spdx-license-identifier|all\s+rights\s+reserved)\b/i,
  // Provenance notes: "Source: https://…", "Source references: - https://…", "Based on …".
  /^\s*(?:sources?|source\s+references?|references?|provenance|see(?:\s+also)?|via|from|credits?|origin(?:al)?|attribution|authors?|adapted\s+from|based\s+on|generated\s+(?:by|from)|last\s+(?:updated|reviewed|synced))\s*[:\-—–]/i,
  /^[\sA-Z0-9_:./=-]+$/, // BEGIN GENERATED, END OF SECTION, ===
];

const rule: Rule = {
  id: "SW002",
  name: "html-comment-instructions",
  severity: "medium",
  appliesTo: ["skill", "instructions"],
  description:
    "Instructions for the agent hidden in HTML comments (`<!-- … -->`) in markdown. Comments are invisible in the rendered file, so reviewers don't see them, but the agent reads the raw text.",
  check(target) {
    return target.files.flatMap((file) => checkFile(file));
  },
};

export default rule;

function checkFile(file: ParsedFile): Finding[] {
  if (!file.markdown) return [];
  const findings: Finding[] = [];
  for (const comment of file.markdown.htmlComments) {
    const verdict = assess(comment.content);
    if (!verdict) continue;
    findings.push(
      findingAt(rule, file, {
        // Point at `<!--`, not at the content.
        offset: comment.offset - 4,
        length: Math.min(comment.content.length + 7, firstLineLength(file.text, comment.offset - 4)),
        message: verdict.strong
          ? "Hidden HTML comment contains prompt-injection phrasing aimed at the agent. Reviewers can't see it in the rendered file. Remove it."
          : "Hidden HTML comment contains instructions for the agent. Reviewers can't see it in the rendered file. Move it into visible text or remove it.",
        confidence: verdict.confidence,
      }),
    );
  }
  return findings;
}

/** Exported for tests: whether a comment body reads like instructions to an agent. */
export function assess(content: string): { confidence: Confidence; strong: boolean } | undefined {
  const text = content.trim();
  if (!text) return undefined;

  const strong = STRONG.some((p) => p.test(text));
  if (!strong && BENIGN.some((p) => p.test(text))) return undefined;
  const words = text.split(/\s+/).length;
  if (!strong && words < 3) return undefined;

  const sentences = text.split(/[.!?;\n]+|\s[-*•]\s|^\s*[-*•]\s|\s\d+\.\s/u).map((s) => s.trim().replace(/^[-*•\d.)\s]+/u, ""));
  const imperative =
    sentences.some((s) => IMPERATIVE_START.test(s.replace(LEADING_ADDRESS, ""))) ||
    YOU_MUST_VERB.test(text) ||
    IMPERATIVE_RU.test(text);
  const address = AGENT_ADDRESS.test(text);
  const payload = PAYLOAD.test(text);

  if (strong) return { confidence: "high", strong: true };
  if ((address || imperative) && payload) return { confidence: "high", strong: false };
  if (address && imperative) return { confidence: "medium", strong: false };
  return undefined;
}

function firstLineLength(text: string, offset: number): number {
  const end = text.indexOf("\n", offset);
  return (end === -1 ? text.length : end) - offset;
}
