// Light JS/TS tokenizer (TRD §6.5 Decision: regex + light tokenization, no full parser).
// Produces a copy of the source with comments blanked (and optionally string contents blanked),
// preserving every offset and newline so line numbers stay correct.

export interface StripOptions {
  /** Replace string and template-literal contents with spaces (quotes are kept). */
  blankStrings?: boolean;
}

const REGEX_PRECEDERS = new Set([
  "(",
  ",",
  "=",
  ":",
  "[",
  "!",
  "&",
  "|",
  "?",
  "{",
  "}",
  ";",
  "+",
  "-",
  "*",
  "%",
  "<",
  ">",
  "~",
  "^",
]);
const REGEX_KEYWORDS = /(?:^|[^\w$])(?:return|typeof|case|do|else|in|of|new|delete|void|throw|yield|await)$/;

function blank(ch: string): string {
  return ch === "\n" || ch === "\r" ? ch : " ";
}

export function stripJs(src: string, opts: StripOptions = {}): string {
  const out: string[] = new Array(src.length);
  const templateDepth: number[] = []; // brace depth at which each open template's ${ started
  let braceDepth = 0;
  let i = 0;
  let lastSignificant = "";
  let lastWordEnd = 0;

  const copy = (c: string) => {
    out[i] = c;
    i++;
  };

  const readString = (quote: string) => {
    copy(src[i]!); // opening quote
    while (i < src.length) {
      const c = src[i]!;
      if (c === "\\") {
        out[i] = opts.blankStrings ? " " : c;
        if (i + 1 < src.length) out[i + 1] = opts.blankStrings ? blank(src[i + 1]!) : src[i + 1]!;
        i += 2;
        continue;
      }
      if (c === quote) {
        copy(c);
        return;
      }
      if (c === "\n" && quote !== "`") {
        copy(c); // unterminated string: stop at newline
        return;
      }
      if (quote === "`" && c === "$" && src[i + 1] === "{") {
        copy("$");
        copy("{");
        templateDepth.push(braceDepth);
        braceDepth++;
        return; // back to code mode inside ${ }
      }
      out[i] = opts.blankStrings ? blank(c) : c;
      i++;
    }
  };

  while (i < src.length) {
    const c = src[i]!;
    const n = src[i + 1];
    if (c === "/" && n === "/") {
      while (i < src.length && src[i] !== "\n") {
        out[i] = " ";
        i++;
      }
      continue;
    }
    if (c === "/" && n === "*") {
      const end = src.indexOf("*/", i + 2);
      const stop = end === -1 ? src.length : end + 2;
      for (; i < stop; i++) out[i] = blank(src[i]!);
      continue;
    }
    if (c === "'" || c === '"' || c === "`") {
      readString(c);
      lastSignificant = c;
      continue;
    }
    if (c === "}" && templateDepth.length && templateDepth[templateDepth.length - 1] === braceDepth - 1) {
      // End of a ${ } expression: resume the template literal.
      // readString copies the char at i (this brace) as its "opening quote", then continues the template.
      templateDepth.pop();
      braceDepth--;
      readString("`");
      lastSignificant = "`";
      continue;
    }
    if (c === "/") {
      const before = src.slice(Math.max(0, lastWordEnd - 12), lastWordEnd);
      const isRegex =
        lastSignificant === "" || REGEX_PRECEDERS.has(lastSignificant) || REGEX_KEYWORDS.test(before);
      if (isRegex) {
        copy(c);
        let inClass = false;
        while (i < src.length && src[i] !== "\n") {
          const r = src[i]!;
          if (r === "\\") {
            copy(r);
            if (i < src.length) copy(src[i]!);
            continue;
          }
          if (r === "[") inClass = true;
          else if (r === "]") inClass = false;
          else if (r === "/" && !inClass) {
            copy(r);
            break;
          }
          copy(r);
        }
        lastSignificant = ")";
        continue;
      }
    }
    if (c === "{") braceDepth++;
    else if (c === "}") braceDepth = Math.max(0, braceDepth - 1);
    if (!/\s/.test(c)) {
      lastSignificant = /[\w$]/.test(c) ? "w" : c;
      if (/[\w$]/.test(c)) lastWordEnd = i + 1;
    }
    copy(c);
  }
  return out.join("");
}
