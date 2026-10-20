import { parse as parseYaml } from "yaml";
import type { CodeBlock, HtmlComment, MarkdownInfo } from "../types.js";
import { locate } from "../text.js";

const FENCE_OPEN = /^( {0,3})(`{3,}|~{3,})(.*)$/;

/**
 * Lightweight markdown structure extraction: frontmatter, fenced code blocks and HTML comments.
 * It is not a full CommonMark parser — just enough for rules to know what is prose, what is code
 * and what is hidden from the rendered view.
 */
export function parseMarkdown(text: string, lineStarts: number[]): MarkdownInfo {
  const info: MarkdownInfo = { bodyOffset: 0, codeBlocks: [], htmlComments: [] };
  const lines = splitLines(text, lineStarts);

  let i = 0;
  if (lines.length > 0 && lines[0]!.text.trimEnd() === "---") {
    const close = lines.findIndex((l, idx) => idx > 0 && /^(---|\.\.\.)\s*$/.test(l.text));
    if (close > 0) {
      const raw = lines
        .slice(1, close)
        .map((l) => l.text)
        .join("\n");
      const frontmatter: NonNullable<MarkdownInfo["frontmatter"]> = {
        raw,
        data: undefined,
        startLine: 1,
        endLine: close + 1,
      };
      try {
        // yaml's default schema has no executable tags; this only builds plain data.
        frontmatter.data = parseYaml(raw, { maxAliasCount: 100 });
      } catch (err) {
        frontmatter.error = err instanceof Error ? err.message.split("\n")[0] : String(err);
      }
      info.frontmatter = frontmatter;
      i = close + 1;
      info.bodyOffset = lines[i]?.offset ?? text.length;
    }
  }

  // Ranges of fenced code, used to avoid treating `<!--` inside code as a comment.
  const codeRanges: Array<[number, number]> = [];
  for (; i < lines.length; i++) {
    const open = FENCE_OPEN.exec(lines[i]!.text);
    if (!open) continue;
    const fence = open[2]!;
    const infoString = open[3]!.trim();
    // A backtick fence's info string may not contain backticks.
    if (fence[0] === "`" && infoString.includes("`")) continue;
    const lang = (infoString.split(/\s+/)[0] ?? "").toLowerCase();
    const closeRe = new RegExp(`^ {0,3}${fence[0] === "`" ? "`" : "~"}{${fence.length},}\\s*$`);
    let j = i + 1;
    while (j < lines.length && !closeRe.test(lines[j]!.text)) j++;
    const first = lines[i + 1];
    const contentStart = first ? first.offset : text.length;
    const contentEnd = j < lines.length ? lines[j]!.offset : text.length;
    const block: CodeBlock = {
      lang,
      content: text.slice(contentStart, contentEnd).replace(/\r?\n$/, ""),
      offset: contentStart,
      line: i + 2,
    };
    info.codeBlocks.push(block);
    codeRanges.push([lines[i]!.offset, j < lines.length ? lines[j]!.offset + lines[j]!.text.length : text.length]);
    i = j;
  }

  const commentRe = /<!--([\s\S]*?)(?:-->|$)/g;
  for (const m of text.slice(info.bodyOffset).matchAll(commentRe)) {
    const offset = info.bodyOffset + m.index;
    if (codeRanges.some(([s, e]) => offset >= s && offset < e)) continue;
    // Inside an inline code span (`<!-- END -->` written as an example): an odd number of backticks before it.
    const lineStart = text.lastIndexOf("\n", offset - 1) + 1;
    if ((text.slice(lineStart, offset).match(/`/g)?.length ?? 0) % 2 === 1) continue;
    const comment: HtmlComment = {
      content: m[1]!,
      offset: offset + 4,
      line: locate(lineStarts, offset).line,
    };
    info.htmlComments.push(comment);
  }

  return info;
}

interface Line {
  text: string;
  offset: number;
}

function splitLines(text: string, lineStarts: number[]): Line[] {
  return lineStarts.map((start, idx) => {
    const next = lineStarts[idx + 1];
    const end = next === undefined ? text.length : next - 1;
    return { text: text.slice(start, end).replace(/\r$/, ""), offset: start };
  });
}
