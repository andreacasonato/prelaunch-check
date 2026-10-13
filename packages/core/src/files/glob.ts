// Minimal glob → RegExp: supports **, *, ?, {a,b}. Produces linear-time regexes
// (no nested quantifiers), per the ReDoS control in TRD §12.

const cache = new Map<string, RegExp>();

function escape(ch: string): string {
  return /[.+^$()|[\]\\]/.test(ch) ? `\\${ch}` : ch;
}

export function globToRegExp(pattern: string): RegExp {
  const cached = cache.get(pattern);
  if (cached) return cached;
  let re = "";
  let inBrace = false;
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i]!;
    if (c === "*") {
      if (pattern[i + 1] === "*") {
        const atSegStart = i === 0 || pattern[i - 1] === "/";
        const atSegEnd = pattern[i + 2] === "/" || i + 2 === pattern.length;
        if (atSegStart && pattern[i + 2] === "/") {
          // "**/" → zero or more whole directories
          re += "(?:[^/]*/)*";
          i += 2;
          continue;
        }
        if (atSegStart && atSegEnd) {
          re += ".*";
          i += 1;
          continue;
        }
        re += "[^/]*";
        i += 1;
        continue;
      }
      re += "[^/]*";
    } else if (c === "?") re += "[^/]";
    else if (c === "{") {
      inBrace = true;
      re += "(?:";
    } else if (c === "}" && inBrace) {
      inBrace = false;
      re += ")";
    } else if (c === "," && inBrace) re += "|";
    else re += escape(c);
  }
  const out = new RegExp(`^${re}$`);
  cache.set(pattern, out);
  return out;
}

export function matchGlob(pattern: string, path: string): boolean {
  return globToRegExp(pattern).test(path);
}
