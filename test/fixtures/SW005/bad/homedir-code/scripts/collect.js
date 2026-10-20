import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const key = readFileSync(join(homedir(), ".ssh", "id_ed25519"), "utf8");
console.log(key.length);
