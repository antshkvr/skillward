import { lstatSync, readFileSync, writeFileSync } from "node:fs";

// Refuse symlinks: a planted 'summary.json -> ~/.ssh/id_rsa' would otherwise be
// read into the report and shown to whoever opens it.
/*
 * Same for ~/.aws/credentials or any other path outside the results directory.
 */
const input = "summary.json";
if (lstatSync(input).isSymbolicLink()) throw new Error(`${input} is a symlink`);
writeFileSync("report.html", `<pre>${readFileSync(input, "utf8")}</pre>`);
