// Copies non-TypeScript assets (rule data) from src/ to dist/ after `tsc`.
import { cpSync } from "node:fs";

cpSync("src/rules/data", "dist/rules/data", { recursive: true });
