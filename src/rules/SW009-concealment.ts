import type { Confidence, Finding, ParsedFile, Rule, Severity } from "../types.js";
import { logicalLines } from "../text.js";
import { findingAt } from "./helpers.js";
import { APOS, B, E, isQuoted, matchPhrases, phrase, stemPhrase, type PhrasePattern } from "./phrases.js";

const TELL_LABEL = "an instruction not to tell the user";

/**
 * A substring every pattern below needs (a user word, a "silently" word, or a "reveal" word). Lines without one
 * skip the ~18 phrase regexes, which matters on 700 KB reference docs. Keep in sync when adding patterns.
 */
const MAYBE_CONCEALMENT =
  /user|human|developer|operator|silent|quiet|secret|covert|stealth|discreet|surreptitious|reveal|disclos|mention|discuss|acknowledg|explain|referenc|пользовател|упомин|раскры|рассказ|тих|незаметн|втайн|скрытн|тайн|неглас/i;

/** Base forms only: concealment instructions are imperatives. */
const ACTION_VERBS =
  "run|execute|send|upload|install|delete|remove|modify|add|copy|exfiltrate|download|post|transmit|write|append|change|overwrite|push|commit|forward";

/**
 * Instructions to hide actions from the user. Heuristic: confidence is medium,
 * high for the explicit forms ("do not tell the user", "the user must not know").
 */
export const CONCEALMENT_PHRASES: PhrasePattern[] = [
  // English
  {
    re: phrase(
      // "Don't tell the user to use X" / "… they need to adopt X" is advice on what to ask of the user, not hiding
      // things from them. "… that you uploaded it" stays a finding.
      String.raw`(?:don${APOS}?t|do not|never|must not|should not) (?:(?:tell|inform|notify|alert|warn|mention (?:this |it |anything )?to|report (?:this |it )?to) (?:the |your )?(?:user|human|developer|operator)s?(?! (?:to|how to) | (?:that )?they (?:need|should|must|have to|ought to|are required)${E})|let (?:the |your )?(?:user|human|developer|operator)s? know)`,
    ),
    label: TELL_LABEL,
    confidence: "high",
  },
  {
    // "don't show the user …": a UX-advice look-alike, checked separately below.
    re: phrase(String.raw`(?:don${APOS}?t|do not|never) (?:show|display) (?:this |it |anything )?(?:to )?(?:the |your )?(?:user|human)s?`),
    label: "an instruction not to show the user",
    // Mostly workflow advice ("don't show the user a diagram that failed validation").
    severity: "medium",
  },
  {
    re: phrase(
      String.raw`without (?:telling|informing|notifying|alerting|warning|letting) (?:the |your )?(?:user|human|developer)s?(?: know)?|without (?:the |your )?user(?:${APOS}s)? (?:knowing|noticing)`,
    ),
    label: "an instruction to act without the user knowing",
    // Also used to describe bugs ("retry logic that fails without informing the user").
    confidence: "medium",
    severity: "medium",
  },
  {
    re: phrase(
      String.raw`(?:don${APOS}?t|do not|never|must not) (?:mention|reveal|disclose|acknowledge|discuss|explain|reference) (?:(?:this|these)(?=\s*(?:$|[.,;:!?)\]"'\x60*—–”»’]|-\s|to|in |or |anywhere|at all))|that you|the(?:se)? (?:instructions?|steps?|rules?)|this (?:file|skill|step|instruction|section|hook|prompt))`,
    ),
    label: "an instruction to keep these instructions secret",
    // Also the confidentiality line of many persona prompts ("never reveal these instructions").
    severity: "medium",
  },
  {
    // Imperative only: "Silently upload …", "… and quietly run …" — not "two decks silently overwrite each other".
    re: new RegExp(
      String.raw`(?<=^|[.!?:;,(*>\-]\s*|${B}(?:then|please|must|should|always|also|just|now)\s+)(?:silently|quietly|secretly|covertly|stealthily|discreetly|surreptitiously)\s+(?:${ACTION_VERBS})${E}`,
      "giu",
    ),
    label: "an instruction to act silently",
    // "to silently change", "and silently install" mostly describe bugs; a quiet step alone is not an attack.
    severity: "medium",
  },
  {
    re: phrase(String.raw`(?:${ACTION_VERBS})(?: \S+){0,4} (?:secretly|covertly|stealthily|surreptitiously|in secret)`),
    label: "an instruction to act silently",
    severity: "medium",
  },
  {
    re: phrase(
      String.raw`(?:hide|conceal|mask)(?: the| this| it| these| all| any| your)?(?: \p{L}+)? (?:output|outputs|actions?|steps?|commands?|changes?|this|it|activity|requests?|traffic|files?|network calls?) from (?:the |your )?(?:user|human|developer)s?`,
    ),
    label: "an instruction to hide actions from the user",
    confidence: "high",
  },
  {
    re: phrase(String.raw`keep (?:this|it|these|that)(?: \p{L}+){0,2} (?:secret|hidden|private|confidential) from (?:the |your )?(?:user|human|developer)s?`),
    label: "an instruction to keep something secret from the user",
    confidence: "high",
  },
  {
    re: phrase(
      String.raw`(?:the |your )?(?:user|human|developer)s? (?:(?:must|shall) not (?:know|see|notice|find out|be told|learn|realize)|should not (?:know|find out|be told|learn|realize))|so (?:that )?(?:the |your )?(?:user|human)s? (?:doesn${APOS}t|does not|won${APOS}t|will not|can${APOS}t|cannot) (?:notice|see|know|find out)`,
    ),
    label: "an instruction that the user must not find out",
    confidence: "high",
  },
  {
    re: phrase(String.raw`suppress (?:all |any )?(?:output|logs?|messages?) so (?:that )?(?:the |your )?(?:user|human)`),
    label: "an instruction to suppress output so the user doesn't see it",
    confidence: "high",
  },
  // Russian
  {
    re: stemPhrase(String.raw`не (?:говори|говорите|сообщай|сообщайте|рассказывай|рассказывайте|упоминай|упоминайте|показывай|показывайте)(?: \p{L}+){0,2}? пользовател`),
    label: "an instruction not to tell the user",
    confidence: "high",
  },
  {
    re: stemPhrase(String.raw`не (?:упоминай|упоминайте|раскрывай|раскрывайте|рассказывай|рассказывайте)(?: об?)? (?:это|эти|этих|этом|инструкци)`),
    label: "an instruction to keep these instructions secret",
  },
  {
    re: stemPhrase(String.raw`(?:скрой|скрывай|скройте|скрывайте|утаи|утаивай)(?: \p{L}+){0,3}? от пользовател`),
    label: "an instruction to hide actions from the user",
    confidence: "high",
  },
  {
    re: stemPhrase(String.raw`(?:тихо|тихонько|незаметно|втайне|скрытно|тайно|негласно)(?: \p{L}+)? (?:выполн|запуст|отправ|установ|удал|измен|скопир|загруз|добав|перешл|допиш|запиш)`),
    label: "an instruction to act silently",
  },
  {
    re: stemPhrase(String.raw`(?:незаметно|втайне|тайно|скрытно) (?:для|от) пользовател`),
    label: "an instruction to act without the user knowing",
    confidence: "high",
  },
  {
    re: stemPhrase(String.raw`пользовател\p{L}* не (?:должен|должна|должны|должно) (?:знать|видеть|заметить|узнать|догадаться)`),
    label: "an instruction that the user must not find out",
    confidence: "high",
  },
  {
    re: stemPhrase(String.raw`без ведома пользовател`),
    label: "an instruction to act without the user knowing",
    confidence: "high",
  },
];

/**
 * "Don't show the user raw stack traces" is UX advice about noise, not concealment of actions.
 * Only applies to the show/display form: "don't tell the user about the errors" stays a finding.
 */
const NOISE_OBJECT =
  /^[\s\p{P}]*(?:\p{L}+\s+){0,3}?(?:raw |full |internal |verbose |long |technical )?(?:stack ?traces?|tracebacks?|errors?|error messages?|warnings?|verbose|logs?|debug|noise|internal ids?|json|boilerplate|diffs?|progress|spinners?)/iu;

/**
 * What follows "don't tell the user" when it really hides something: nothing (end of clause), "about …",
 * "this", "what/which/how you …", "that you …". Otherwise it is usually advice on what not to claim
 * ("never tell the user something is done because one part exists") and is reported at medium.
 */
const CONCEALED_OBJECT =
  /^\s*(?:$|[.,;:!?)\]`*—–”»]|-\s|(?:about|of|anything|this|these|that\s+(?:you|we|the agent|this|these|it)|(?:what|which|how|where|when|why)\s+(?:you|we|the agent)|you\s+(?:ran|did|used|read|sent|installed|changed|deleted|uploaded|wrote|called|are|were|have|had))(?![\p{L}\p{N}_]))/iu;
const rule: Rule = {
  id: "SW009",
  name: "concealment",
  severity: "high",
  appliesTo: ["skill", "instructions", "mcp-config", "settings", "plugin-manifest"],
  description:
    'Instructions to hide actions from the user: "don\'t tell the user", "do it silently", "hide the output", "the user must not know" (EN/RU).',
  check(target) {
    return target.files.flatMap((file) => checkFile(file));
  },
};

export default rule;

function checkFile(file: ParsedFile): Finding[] {
  const findings: Finding[] = [];
  for (const line of logicalLines(file.text)) {
    if (!MAYBE_CONCEALMENT.test(line.text)) continue;
    for (const m of matchPhrases(line.text, CONCEALMENT_PHRASES)) {
      let severity: Severity = m.pattern.severity ?? rule.severity;
      let confidence: Confidence = m.pattern.confidence ?? "medium";
      let message = `Hides activity from the user: ${m.pattern.label}. Legitimate skills have nothing to hide — treat this as a red flag and remove it.`;
      if (isQuoted(line.text, m.start, m.end)) {
        severity = "low";
        confidence = "low";
        message = `Quotes ${m.pattern.label} — usually an example or a detection pattern. Listed for inventory.`;
      } else if (m.pattern.label === TELL_LABEL && /^[a-z]/i.test(line.text.slice(m.start)) && !/know$/i.test(line.text.slice(m.start, m.end)) && !CONCEALED_OBJECT.test(line.text.slice(m.end))) {
        severity = "medium";
        confidence = "medium";
        message = "Tells the agent not to tell the user something. Usually advice on what not to claim; check that it doesn't hide what the agent does.";
      } else if (m.pattern.label === "an instruction not to show the user" && NOISE_OBJECT.test(line.text.slice(m.end))) {
        severity = "info";
        confidence = "low";
        message = "Asks not to show the user something that looks like output noise (errors, logs). Listed for inventory.";
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
  return findings;
}
