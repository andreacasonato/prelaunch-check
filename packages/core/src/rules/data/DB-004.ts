import type { RawFinding, Rule } from "../../types.js";
import { at, DB_BOOK, FIREBASE_INSECURE } from "./common.js";
import { hasWrite, loadFirebase } from "./firebase.js";

export const DB_004: Rule = {
  meta: {
    id: "DB-004",
    title: "Firebase rules allow open access",
    category: "data",
    severity: "critical",
    confidence: "high",
    owasp: "A01",
    requires: ["files"],
    appliesWhen: (p) => p.backends.includes("firebase"),
    summary:
      'Finds Firestore/Storage rules that allow writes with `if true` or no condition, and Realtime Database rules with ".read": true or ".write": true.',
    why: "Your Firebase config ships in your front end, so anyone can talk to your database directly. With open rules they can read everything, overwrite it or delete it. Firebase's own docs say never to use this in production.",
    fix: [
      "Replace open rules with rules that check who is asking, for example `allow read, write: if request.auth != null && request.auth.uid == userId;` inside `match /users/{userId}`.",
      "Deny by default: start from `allow read, write: if false;` and open only what each collection needs.",
      "Test your rules with the Firebase Emulator Suite before deploying.",
    ],
    fixPromptTemplate:
      "In `{{path}}` line {{line}}, the Firebase rule `{{detail.rule}}` allows anyone to {{detail.access}}. Rewrite the rules so each collection only allows the signed-in owner (request.auth.uid == the document's owner id), deny everything else by default, and add emulator tests that prove a logged-out user and a different user are rejected.",
    falsePositiveNotes:
      "Read-only `allow read: if true` on genuinely public collections is not reported by this rule. Rules deployed from the console instead of files are invisible to a folder scan.",
    sources: [
      { title: "Firebase: Avoid insecure rules", url: FIREBASE_INSECURE },
      { title: "Locking Down the Database", book: DB_BOOK },
    ],
  },
  async check(ctx) {
    const { rules, rtdb, texts } = await loadFirebase(ctx.files!);
    const out: RawFinding[] = [];
    for (const r of rules) {
      const open = r.condition === null || r.condition === "true";
      if (!open || !hasWrite(r.ops)) continue;
      const text = texts.get(r.file)!;
      const f = at("DB-004", r.file, text, r.offset, r.length);
      f.title = `${r.file.includes("storage") ? "Storage" : "Firestore"} rule lets anyone ${r.ops.join(", ")}`;
      f.evidence.detail = {
        rule: text.slice(r.offset, r.offset + r.length),
        access: r.ops.join(", "),
        path: r.path,
      };
      out.push(f);
    }
    for (const r of rtdb) {
      if (r.value !== "true") continue;
      const text = texts.get(r.file)!;
      const f = at("DB-004", r.file, text, r.offset, r.length);
      f.title = `Realtime Database rule lets anyone ${r.kind === ".write" ? "write" : "read"}`;
      f.evidence.detail = { rule: text.slice(r.offset, r.offset + r.length), access: r.kind.slice(1) };
      out.push(f);
    }
    return out;
  },
};
