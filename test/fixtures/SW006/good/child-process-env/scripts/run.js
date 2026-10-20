import { spawn } from "node:child_process";

const env = { ...process.env, NODE_ENV: "test" };
spawn("npm", ["test"], { env, stdio: "inherit" });
console.log(process.env.HOME);
