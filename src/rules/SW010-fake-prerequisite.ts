import type { Confidence, Finding, ParsedFile, Rule, Severity } from "../types.js";
import { logicalLines, type LogicalLine, execAll } from "../text.js";
import { findingAt } from "./helpers.js";
import { matchPhrases, phrase, stemPhrase, type PhrasePattern } from "./phrases.js";
import { PASTE_HOSTS } from "./SW007-suspicious-egress.js";

/** "Before using this skill…", "You must first…", "Перед использованием…". */
export const PREREQUISITE_PHRASES: PhrasePattern[] = [
  {
    re: phrase(
      String.raw`before (?:using|you (?:use|start|begin|run|continue|proceed)|running|first use|proceeding|anything else|doing anything)|you (?:must|need to|have to|should) first|first,? (?:run|install|download|execute|launch)|prerequisites?|required setup|setup required|one-time setup|make sure (?:to|you) (?:install|run|download|execute)|(?:requires?|required|need) (?:you )?to (?:install|run|download|execute)`,
    ),
    label: "prerequisite",
  },
  {
    re: stemPhrase(
      String.raw`перед (?:использовани|началом|запуском|работой)|(?:сначала|обязательно|предварительно) (?:установи|запусти|скачай|выполни|загрузи)|необходимо (?:установить|запустить|скачать|выполнить|загрузить)|требуется (?:установить|запустить|скачать)`,
    ),
    label: "prerequisite",
  },
];

const EXECUTABLE_EXT = String.raw`exe|msi|dmg|pkg|sh|bash|ps1|psm1|bat|cmd|command|appimage|deb|rpm|jar|bin|run|vsix|scr|app`;
const ARCHIVE_EXT = String.raw`zip|tar\.gz|tgz|tar\.xz|txz|tar\.bz2|7z|rar|whl|gem|nupkg`;
const URL_TAIL = String.raw`(?:[?#][^\s"'\x60)<>]*)?(?![\w./-])`;
/** Scheme, host and a path: the extension must be in the path, not the TLD (`https://bun.sh`, `https://tauri.app/`). */
const URL_PATH = String.raw`https?://[^\s/"'\x60)<>]+/[^\s"'\x60)<>]*?`;

/** Something external to download and run. */
interface ArtifactPattern {
  re: RegExp;
  label: string;
  /** An executable itself, not a package or an archive. */
  strong: boolean;
  /** Only an artifact when the text also says to run/install it (a data .zip is not a prerequisite binary). */
  needsRunIntent?: boolean;
}

export const ARTIFACTS: ArtifactPattern[] = [
  {
    re: new RegExp(String.raw`${URL_PATH}\.(?:${EXECUTABLE_EXT})${URL_TAIL}`, "gi"),
    label: "an executable from a URL",
    strong: true,
  },
  {
    re: /https?:\/\/github\.com\/[^\s/"'`]+\/[^\s/"'`]+\/releases\/(?:download|latest\/download)\/[^\s"'`)<>]+/gi,
    label: "a release binary",
    strong: true,
  },
  {
    re: /\b(?:curl|wget)\b[^\n]{0,400}?(?:\s-[a-zA-Z]*[oO]\b|\s--output\b|\s-O\b)[^\n]{0,400}?(?:&&|;)\s*chmod\s+(?:\+x|[0-7]*7[0-7]*)\b/gi,
    label: "a downloaded file made executable",
    strong: true,
  },
  {
    re: /\bpip[\d.]*\s+install\s+(?:-\S+\s+)*(?:git\+|https?:\/\/)\S+|\bnpm\s+(?:i|install)\s+(?:-\S+\s+)*https?:\/\/\S+|\bnpm\s+(?:i|install)\s+(?:-\S+\s+)*\S+\.tgz\b|\bcargo\s+install\s+(?:-\S+\s+)*--git\s+https?:\/\/\S+/gi,
    label: "a package installed straight from a URL",
    strong: false,
  },
  {
    re: new RegExp(String.raw`${URL_PATH}\.(?:${ARCHIVE_EXT})${URL_TAIL}`, "gi"),
    label: "an archive from a URL",
    strong: false,
    needsRunIntent: true,
  },
];

/** "download and run", "скачай и запусти": the instruction is to execute, not just fetch. */
const RUN_INTENT =
  /(?<![\p{L}])(?:download and (?:run|execute|install|launch|open)|run|execute|launch|install|chmod|double-click|запусти\p{L}*|выполни\p{L}*|установи\p{L}*|скачай\p{L}*\s+и\s+(?:запусти|установи|выполни)\p{L}*)(?![\p{L}])/iu;

/** Asking the human to run something — a social-engineering step the agent shouldn't relay. */
const ASK_USER_TO_RUN: PhrasePattern[] = [
  {
    re: phrase(
      // The object must be a command or the terminal must be named: "ask the user to paste the comments" is fine.
      String.raw`(?:ask|tell|instruct|have|get) (?:the |your )?(?:user|human|developer)s? to (?:run|paste|execute|copy and paste|enter|type) (?:this|these|the following|a|the)(?: \p{L}+)? (?:command|commands|script|snippet|one-liner)(?: (?:in|into) (?:their|a|the|your) (?:terminal|shell|console|powershell|command prompt))?|(?:ask|tell|instruct|have|get) (?:the |your )?(?:user|human|developer)s? to (?:run|paste|execute|copy and paste|enter|type)[^.!?\n]{0,60}? (?:in|into) (?:their|a|the|your) (?:terminal|shell|console|powershell|command prompt)`,
    ),
    label: "asks the user to run a command",
  },
  {
    re: stemPhrase(String.raw`(?:попроси|попросите|скажи|скажите) пользовател\p{L}* (?:выполни|запусти|вставить|вставь|ввести|введ|скопировать)`),
    label: "asks the user to run a command",
  },
];

const NEGATED = /(?:\bnot|n['’]t|\bnever|\bno need to|\binstead of)[*_]*\s+(?:\p{L}+\s+){0,2}$/iu;
/** The step happens in the user's own terminal: pasting, or a named shell. */
const TERMINAL_STEP = /\b(?:paste|copy and paste|terminal|shell|console|powershell|command prompt)\b/i;
/** Password-protected archives hide their content from antivirus scanners — a hallmark of malware delivery. */
const PASSWORD_ARCHIVE =
  /(?:extract|unzip|unpack|unrar|archive|\.zip|\.7z|\.rar|архив|распак)[^\n]{0,80}(?:\bpassword\b|\bpassphrase\b|\bpass(?:word)?\s*[:=]|пароль)|(?:\bpassword\b|\bpassphrase\b|\bpass(?:word)?\s*[:=]|пароль)[^\n]{0,80}(?:extract|unzip|unpack|unrar|archive|\.zip|\.7z|\.rar|архив|распак)/iu;

/** How many logical lines around a prerequisite phrase may hold the artifact. */
const WINDOW = 3;

/** A link to a page on a paste site (not the bare domain): where off-repo "activation" commands live. */
const PASTE_URL = new RegExp(
  String.raw`https?://(?:[\w-]+\.)*(?:${PASTE_HOSTS.map((h) => h.replace(/\./g, "\\.")).join("|")})/[\w./?=&%-]+`,
  "gi",
);
/** Running or pasting something in the user's terminal. */
const TERMINAL_RUN =
  /\b(?:paste|copy|copying|run|running|execute|enter|type)\b[^.!?\n]{0,60}\b(?:terminal|shell|console|powershell|command prompt|cmd)\b|\b(?:terminal|shell|console|powershell|command prompt)\b[^.!?\n]{0,40}\b(?:paste|run|execute|command)/i;
/** How far (in lines) a terminal step may be from the paste link. */
const PASTE_WINDOW = 8;

const rule: Rule = {
  id: "SW010",
  name: "fake-prerequisite",
  severity: "medium",
  appliesTo: ["skill", "instructions"],
  description:
    'A "prerequisite" to download and run an external binary or script ("before using this skill, install …" + an executable URL), or asking the user to paste a command into their terminal.',
  check(target) {
    return target.files.flatMap((file) => checkFile(file));
  },
};

export default rule;

function checkFile(file: ParsedFile): Finding[] {
  const lines = logicalLines(file.text);
  const findings: Finding[] = [];
  const reported = new Map<number, Array<[number, number]>>();
  const report = (line: LogicalLine, start: number, end: number, message: string, confidence: Confidence, severity: Severity = rule.severity) => {
    // One finding per artifact: a release URL ending in .exe matches two patterns.
    const ranges = reported.get(line.line) ?? [];
    if (ranges.some(([s, e]) => start < e && end > s)) return;
    ranges.push([start, end]);
    reported.set(line.line, ranges);
    findings.push(findingAt(rule, file, { offset: line.offsets[start]!, length: end - start, message, confidence, severity }));
  };

  const prerequisiteLines = new Set<number>();
  lines.forEach((line, i) => {
    if (matchPhrases(line.text, PREREQUISITE_PHRASES).length > 0) prerequisiteLines.add(i);
  });

  // "Open this activation page (a paste site) and run the command in Terminal": the command lives off-repo,
  // can change at any time and can't be reviewed here — the ClawHavoc macOS pattern.
  const terminalLines = lines.map((l) => {
    const at = l.text.search(TERMINAL_RUN);
    return at !== -1 && !NEGATED.test(l.text.slice(Math.max(0, at - 30), at));
  });
  lines.forEach((line, i) => {
    PASTE_URL.lastIndex = 0;
    for (const m of execAll(PASTE_URL, line.text)) {
      if (!terminalLines.slice(Math.max(0, i - PASTE_WINDOW), i + PASTE_WINDOW + 1).some(Boolean)) continue;
      report(
        line,
        m.index,
        m.index + m[0].length,
        "Sends the user to a paste site for a command to run in their terminal. The command lives outside the skill, can change at any time and can't be reviewed — a known malware-delivery pattern. Remove it.",
        "medium",
        "high",
      );
    }
  });

  lines.forEach((line, i) => {
    for (const m of matchPhrases(line.text, ASK_USER_TO_RUN)) {
      // "Do not ask the user to paste a shell command. Run it yourself." is the opposite instruction.
      if (NEGATED.test(line.text.slice(Math.max(0, m.start - 30), m.start))) continue;
      // "Ask the user to run the install command if that fails" is an ordinary fallback; naming the terminal or
      // pasting is the pattern of getting a human to run what the agent can't (or shouldn't).
      const said = line.text.slice(m.start, m.end);
      const terminal = TERMINAL_STEP.test(said) || /\p{Script=Cyrillic}/u.test(said);
      report(
        line,
        m.start,
        m.end,
        terminal
          ? "Tells the agent to have the user run a command themselves. This hands the attack to the human, outside every agent safeguard. Remove it."
          : "Tells the agent to have the user run a command, e.g. as a fallback. Check that it is a command you would run yourself.",
        terminal ? "medium" : "low",
        terminal ? "medium" : "low",
      );
    }

    const near = [...prerequisiteLines].filter((p) => Math.abs(p - i) <= WINDOW);
    if (near.length === 0) return;
    const runIntent = near.some((p) => RUN_INTENT.test(lines[p]!.text)) || RUN_INTENT.test(line.text);
    for (const { re, label, strong, needsRunIntent } of ARTIFACTS) {
      re.lastIndex = 0;
      for (const m of execAll(re, line.text)) {
        if (needsRunIntent && !runIntent) continue;
        // Same line or the next one: a password elsewhere in the section (the tool's admin password) is unrelated.
        if (PASSWORD_ARCHIVE.test(lines.slice(i, i + 2).map((l) => l.text).join("\n"))) {
          report(
            line,
            m.index,
            m.index + m[0].length,
            `A "prerequisite" asks to download and run ${label} from a password-protected archive. Passwords keep antivirus from scanning the content — a hallmark of malware delivery. Do not run it.`,
            "high",
            "high",
          );
          continue;
        }
        report(
          line,
          m.index,
          m.index + m[0].length,
          `A "prerequisite" asks to download and run ${label}. Fake setup steps are a common way to get malware executed. Install tools from a package manager you trust, or remove the step.`,
          strong && runIntent ? "high" : "medium",
        );
      }
    }
  });
  return findings;
}
