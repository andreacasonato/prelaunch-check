import type { RawFinding, Rule } from "../../types.js";
import { at, FIREBASE_INSECURE } from "./common.js";
import { hasWrite, loadFirebase } from "./firebase.js";

const SIGNED_IN_ONLY = /^\(?\s*request\.auth(?:\.uid)?\s*!=\s*null\s*\)?$/;
const RTDB_SIGNED_IN_ONLY = /^\(?\s*auth(?:\.uid)?\s*!=\s*null\s*\)?$/;

export const DB_005: Rule = {
  meta: {
    id: "DB-005",
    title: "Firebase rule grants access to any signed-in user",
    category: "data",
    severity: "medium",
    confidence: "medium",
    owasp: "A01",
    requires: ["files"],
    appliesWhen: (p) => p.backends.includes("firebase"),
    summary:
      "Finds write rules whose only condition is `request.auth != null` (Realtime Database: `auth != null`).",
    why: "Anyone can create an account in most apps. A rule that only checks that someone is signed in lets every user change every other user's data.",
    fix: [
      "Check ownership, not just sign-in: `allow write: if request.auth != null && request.auth.uid == resource.data.ownerId;` (use `request.resource.data` for creates).",
      'Realtime Database: `".write": "auth != null && auth.uid === $uid"` under a `$uid` path.',
    ],
    fixPromptTemplate:
      "In `{{path}}` line {{line}}, the Firebase rule only checks that a user is signed in, so any user can write any document. Change it to also check ownership (request.auth.uid == the document owner's id, using request.resource.data for creates) and add an emulator test proving user B can't modify user A's data.",
    falsePositiveNotes:
      "Some collections are meant to be shared by all members (for example a public chat); confirm that's intended.",
    sources: [{ title: "Firebase: Avoid insecure rules", url: FIREBASE_INSECURE }],
  },
  async check(ctx) {
    const { rules, rtdb, texts } = await loadFirebase(ctx.files!);
    const out: RawFinding[] = [];
    for (const r of rules) {
      if (r.condition === null || !hasWrite(r.ops) || !SIGNED_IN_ONLY.test(r.condition)) continue;
      out.push({
        ...at("DB-005", r.file, texts.get(r.file)!, r.offset, r.length),
        title: `Any signed-in user can ${r.ops.join(", ")}`,
      });
    }
    for (const r of rtdb) {
      if (r.kind !== ".write" || !RTDB_SIGNED_IN_ONLY.test(r.value)) continue;
      out.push({
        ...at("DB-005", r.file, texts.get(r.file)!, r.offset, r.length),
        title: "Any signed-in user can write",
      });
    }
    return out;
  },
};
