// FileSource over the File[] from <input webkitdirectory> (TRD §11). The FileList contains the whole
// folder, node_modules included, so core filters paths BEFORE anything is read: readText() is only
// called for files that survive the ignore rules.
import type { FileEntry, FileSource } from "@prelaunch-check/core";

/** webkitRelativePath is "picked-folder/sub/file"; scanning is relative to the picked folder. */
export function relativePath(file: File): string {
  const rel = (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name;
  const i = rel.indexOf("/");
  return i === -1 ? rel : rel.slice(i + 1);
}

export function rootName(files: File[]): string {
  const rel = (files[0] as (File & { webkitRelativePath?: string }) | undefined)?.webkitRelativePath ?? "";
  return rel.split("/")[0] || "project";
}

export class BrowserFileSource implements FileSource {
  private readonly byPath = new Map<string, File>();

  constructor(files: File[], pathOf: (f: File) => string = relativePath) {
    for (const f of files) this.byPath.set(pathOf(f), f);
  }

  async *list(): AsyncIterable<FileEntry> {
    for (const [path, f] of this.byPath) yield { path, size: f.size };
  }

  async readText(path: string): Promise<string | null> {
    const f = this.byPath.get(path);
    if (!f) return null;
    try {
      return await f.text();
    } catch {
      return null;
    }
  }
}
