import { readFileSync } from "node:fs";

/**
 * Command vocabulary for rules, loaded from `data/vocabulary.json`.
 *
 * Some command names (PowerShell download-and-execute cmdlets and friends) are kept out of the
 * JavaScript we ship: ML-based antivirus engines flag a script that contains them, even inside
 * detection regexes, and quarantine it — which breaks the scanner on Windows. Data files are not
 * judged as scripts. Rules build their regexes from this vocabulary at load time.
 */
const VOCABULARY = JSON.parse(readFileSync(new URL("./data/vocabulary.json", import.meta.url), "utf8")) as Record<
  string,
  string[] | string
>;

export type VocabularyGroup =
  | "psFetch"
  | "psEval"
  | "psHttpClient"
  | "psClientRead"
  | "psDecode"
  | "psSocket"
  | "psBits";

/** Rebuilds a regex literal with `__group__` placeholders replaced by the vocabulary groups. */
export function withVocab(re: RegExp): RegExp {
  return new RegExp(
    re.source.replace(/__(\w+)__/g, (_, g: string) => vocab(g as VocabularyGroup)),
    re.flags,
  );
}

/** The group as a non-capturing regex alternation, e.g. `(?:a|b)`. */
export function vocab(...groups: VocabularyGroup[]): string {
  const parts = groups.flatMap((g) => {
    const entries = VOCABULARY[g];
    if (!Array.isArray(entries) || entries.length === 0) throw new Error(`rule vocabulary group "${g}" is missing`);
    return entries;
  });
  return `(?:${parts.join("|")})`;
}
