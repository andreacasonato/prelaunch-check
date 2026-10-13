import { createInterface } from "node:readline/promises";
import { main } from "./main.js";

const io = {
  stdout: (t: string) => void process.stdout.write(t),
  stderr: (t: string) => void process.stderr.write(t),
  env: process.env,
  cwd: process.cwd(),
  isTTY: Boolean(process.stdout.isTTY),
  columns: process.stdout.columns || 100,
  fetch: globalThis.fetch.bind(globalThis),
  now: () => new Date(),
  async confirm(question: string) {
    if (!process.stdin.isTTY) return false;
    const rl = createInterface({ input: process.stdin, output: process.stderr });
    try {
      return /^y(es)?$/i.test((await rl.question(question)).trim());
    } finally {
      rl.close();
    }
  },
};

main(process.argv.slice(2), io).then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 3;
  },
);
