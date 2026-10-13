// Copies the repo's README, LICENSE and NOTICE into the package before `npm pack` / `npm publish`.
import { copyFile } from "node:fs/promises";

for (const name of ["README.md", "LICENSE", "NOTICE"]) {
  await copyFile(new URL(`../../${name}`, import.meta.url), new URL(`./${name}`, import.meta.url));
}
