// In-memory FileSource for tests and for callers that already hold file contents.
import type { FileEntry, FileSource } from "../types.js";

const decoder = new TextDecoder("utf-8");
const encoder = new TextEncoder();

export class MemoryFileSource implements FileSource {
  private readonly files: Map<string, string | Uint8Array>;
  private readonly tracked: Set<string> | null;

  constructor(files: Record<string, string | Uint8Array>, options: { gitTracked?: string[] } = {}) {
    this.files = new Map(Object.entries(files));
    this.tracked = options.gitTracked ? new Set(options.gitTracked) : null;
  }

  async *list(): AsyncIterable<FileEntry> {
    for (const [path, content] of this.files) {
      const size = typeof content === "string" ? encoder.encode(content).length : content.length;
      yield { path, size };
    }
  }

  async readText(path: string): Promise<string | null> {
    const content = this.files.get(path);
    if (content === undefined) return null;
    return typeof content === "string" ? content : decoder.decode(content);
  }

  async isGitTracked(path: string): Promise<boolean | null> {
    return this.tracked ? this.tracked.has(path) : null;
  }
}
