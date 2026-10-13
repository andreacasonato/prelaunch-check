// A small .gitignore matcher (https://git-scm.com/docs/gitignore) used by SEC-004 and CFG-002.
// Supports nested .gitignore files, negation, anchoring, directory-only patterns, *, ?, **, [classes].
// Regexes are built without nested quantifiers (linear-time, TRD §12).

interface GitignoreRule {
  base: string; // directory of the .gitignore, "" for root, else "dir/"
  negate: boolean;
  dirOnly: boolean;
  re: RegExp;
}

function escapeRe(ch: string): string {
  return /[.+^$(){}|\\]/.test(ch) ? `\\${ch}` : ch;
}

function patternToRegExp(pattern: string, anchored: boolean): RegExp {
  let re = "";
  let i = 0;
  if (pattern.startsWith("**/")) {
    re += "(?:[^/]*/)*";
    i = 3;
  }
  for (; i < pattern.length; i++) {
    const c = pattern[i]!;
    if (c === "*") {
      if (pattern[i + 1] === "*") {
        if (pattern[i + 2] === "/" && (i === 0 || pattern[i - 1] === "/")) {
          re += "(?:[^/]*/)*";
          i += 2;
          continue;
        }
        if (i + 2 === pattern.length && pattern[i - 1] === "/") {
          re += ".*";
          i += 1;
          continue;
        }
      }
      re += "[^/]*";
    } else if (c === "?") re += "[^/]";
    else if (c === "[") {
      const close = pattern.indexOf("]", i + 2);
      if (close === -1) re += "\\[";
      else {
        let cls = pattern.slice(i + 1, close);
        if (cls.startsWith("!")) cls = "^" + cls.slice(1);
        re += `[${cls.replace(/\\/g, "\\\\")}]`;
        i = close;
      }
    } else if (c === "\\" && i + 1 < pattern.length) {
      re += escapeRe(pattern[i + 1]!);
      i++;
    } else re += escapeRe(c);
  }
  return new RegExp(anchored ? `^${re}$` : `^(?:[^/]*/)*${re}$`);
}

export function parseGitignore(content: string, base = ""): GitignoreRule[] {
  const rules: GitignoreRule[] = [];
  for (let line of content.split(/\r?\n/)) {
    if (line === "" || line.startsWith("#")) continue;
    // Trailing spaces are ignored unless escaped.
    line = line.replace(/(?<!\\)\s+$/, "");
    if (line === "") continue;
    let negate = false;
    if (line.startsWith("!")) {
      negate = true;
      line = line.slice(1);
    } else if (line.startsWith("\\!") || line.startsWith("\\#")) line = line.slice(1);
    let dirOnly = false;
    if (line.endsWith("/")) {
      dirOnly = true;
      line = line.slice(0, -1);
    }
    if (line === "") continue;
    const anchored = line.includes("/");
    if (line.startsWith("/")) line = line.slice(1);
    rules.push({ base, negate, dirOnly, re: patternToRegExp(line, anchored) });
  }
  return rules;
}

export interface GitignoreMatcher {
  isIgnored(path: string): boolean;
  /** True if any .gitignore file was provided. */
  readonly hasRules: boolean;
}

/** `files` maps .gitignore paths (e.g. ".gitignore", "apps/web/.gitignore") to their content. */
export function createGitignoreMatcher(files: Record<string, string>): GitignoreMatcher {
  const ordered = Object.keys(files).sort(
    (a, b) => a.split("/").length - b.split("/").length || (a < b ? -1 : 1),
  );
  const rules: GitignoreRule[] = [];
  for (const p of ordered) {
    const base = p.slice(0, p.length - ".gitignore".length);
    rules.push(...parseGitignore(files[p]!, base));
  }

  function match(path: string, isDir: boolean): boolean | null {
    let result: boolean | null = null;
    for (const r of rules) {
      if (r.base && !path.startsWith(r.base)) continue;
      if (r.dirOnly && !isDir) continue;
      if (r.re.test(path.slice(r.base.length))) result = !r.negate;
    }
    return result;
  }

  return {
    hasRules: rules.length > 0,
    isIgnored(path: string): boolean {
      // A file inside an ignored directory can't be re-included (git semantics).
      const parts = path.split("/");
      for (let i = 1; i < parts.length; i++) {
        if (match(parts.slice(0, i).join("/"), true) === true) return true;
      }
      return match(path, false) === true;
    },
  };
}
