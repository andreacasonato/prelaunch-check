// FileSource over node:fs. Never follows symlinks and never reads outside the scan root.
import { opendir, readFile, stat } from "node:fs/promises";
import { execFile } from "node:child_process";
import { join, resolve, sep } from "node:path";
import { promisify } from "node:util";
import { isIgnoredDir, type FileEntry, type FileSource } from "@prelaunch-check/core";

const exec = promisify(execFile);

export class NodeFileSource implements FileSource {
  readonly root: string;
  private tracked: Promise<Set<string> | null> | null = null;

  constructor(root: string) {
    this.root = resolve(root);
  }

  async *list(): AsyncIterable<FileEntry> {
    yield* this.walk("", false);
  }

  private async *walk(rel: string, ignored: boolean): AsyncGenerator<FileEntry> {
    let dir;
    try {
      dir = await opendir(join(this.root, rel));
    } catch {
      return;
    }
    const entries: Array<{ name: string; isDir: boolean; isFile: boolean }> = [];
    for await (const d of dir) {
      if (d.isSymbolicLink()) continue; // never follow links out of the project
      entries.push({ name: d.name, isDir: d.isDirectory(), isFile: d.isFile() });
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : 1));
    for (const e of entries) {
      const path = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDir) {
        if (path === ".git" || path.endsWith("/.git")) {
          // Only HEAD and config are used (stack detection); objects are never walked.
          for (const name of ["HEAD", "config"]) {
            try {
              const s = await stat(join(this.root, path, name));
              if (s.isFile()) yield { path: `${path}/${name}`, size: s.size };
            } catch {
              /* missing */
            }
          }
          continue;
        }
        // Ignored folders (node_modules…) are listed for the skip count, without stat calls.
        yield* this.walk(path, ignored || isIgnoredDir(path));
      } else if (e.isFile) {
        if (ignored) {
          yield { path, size: 0 };
          continue;
        }
        try {
          yield { path, size: (await stat(join(this.root, path))).size };
        } catch {
          /* vanished */
        }
      }
    }
  }

  private inside(path: string): string | null {
    const full = resolve(this.root, path);
    return full === this.root || full.startsWith(this.root + sep) ? full : null;
  }

  async readText(path: string): Promise<string | null> {
    const full = this.inside(path);
    if (!full) return null;
    try {
      return await readFile(full, "utf8");
    } catch {
      return null;
    }
  }

  async isGitTracked(path: string): Promise<boolean | null> {
    this.tracked ??= (async () => {
      try {
        const { stdout } = await exec("git", ["ls-files", "-z"], {
          cwd: this.root,
          maxBuffer: 256 * 1024 * 1024,
        });
        return new Set(stdout.split("\0").filter(Boolean));
      } catch {
        return null; // not a git repo, or git missing
      }
    })();
    const set = await this.tracked;
    return set ? set.has(path) : null;
  }
}
