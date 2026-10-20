import { readFileSync } from "node:fs";

/** Package version, read from package.json (one level above both src/ and dist/). */
export const VERSION: string = (
  JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string }
).version;
