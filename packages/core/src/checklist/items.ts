// Manual checklist MAN-001…018 (TRD §6.7). Data only: never affects the score.
import type { ChecklistItem } from "../types.js";

const APPENDIX_A = "Creating a Secure App — Appendix A: Master Security & Launch Checklist";
const VERIFY = "Creating a Secure App — Verify: Hack Yourself Before Someone Else Does";

const BREAK_IN = "Try to break in";
const ABUSE = "Abuse & cost";
const AUTH = "Auth & data";
const OPS = "Operations";

export const CHECKLIST: readonly ChecklistItem[] = [
  {
    id: "MAN-001",
    group: BREAK_IN,
    title: "Can I give myself premium or credits by editing my own data?",
    howToTest:
      "Sign in as a normal user, then use the browser console or your database client with that user's session to update your own profile's plan, role or credits.",
    why: "Access rules often let users edit their own row, including columns that control money or power. If that update succeeds, anyone can upgrade themselves for free.",
    source: VERIFY,
  },
  {
    id: "MAN-002",
    group: BREAK_IN,
    title: "Can I read someone else's data by changing an ID in a request?",
    howToTest:
      "Open the Network tab, find a request that loads your data by ID, and replay it with another user's ID (create a second test account for this).",
    why: "Checking that someone is logged in isn't the same as checking that the data belongs to them. This is the most common authorization bug.",
    source: VERIFY,
  },
  {
    id: "MAN-003",
    group: BREAK_IN,
    title: "Can I press the expensive button past its limit?",
    howToTest:
      "Click the action that costs you money (AI call, email, export) many times quickly, and from two tabs at once. Check whether the limit holds on the server.",
    why: "Limits enforced only in the browser can be bypassed, and each extra call is billed to you.",
    source: VERIFY,
  },
  {
    id: "MAN-004",
    group: BREAK_IN,
    title: "Logged-out test: no data or paid features reachable",
    howToTest:
      "Open a private window without signing in. Visit every page and API URL you know about, including deep links to user content.",
    why: "Pages that hide content with front-end checks often still return the data from the API to anyone.",
    source: VERIFY,
  },
  {
    id: "MAN-005",
    group: BREAK_IN,
    title: "Every endpoint classified as anonymous, user or admin; admin routes verified",
    howToTest:
      "Use the endpoint inventory in this report. For each route, write down who should reach it, then call admin routes as a normal user and as a logged-out visitor.",
    why: "Admin endpoints without a server-side role check are a direct path to taking over the app.",
    source: APPENDIX_A,
  },
  {
    id: "MAN-006",
    group: ABUSE,
    title: "Server-side rate limits on login, sign-up and expensive endpoints",
    howToTest:
      "Send 50 rapid requests to login, sign-up and any AI or email endpoint. Confirm you get blocked, and that per-user limits are stored somewhere users can't edit.",
    why: "Without rate limits, attackers can guess passwords, create spam accounts, or run up your bill.",
    source: APPENDIX_A,
  },
  {
    id: "MAN-007",
    group: ABUSE,
    title: "Budget caps and spend alerts on every paid service",
    howToTest:
      "Open the billing settings of each provider (cloud, AI API, email, database) and confirm a hard cap or alert is set.",
    why: "A leaked key or a loop bug can cost thousands overnight. Caps turn a disaster into an email.",
    source: APPENDIX_A,
  },
  {
    id: "MAN-008",
    group: AUTH,
    title: "Paywall and roles enforced on the server, not in the browser",
    howToTest:
      "With a free account, call the paid feature's API directly (copy it from the Network tab). It should refuse.",
    why: "Anything enforced only in front-end code can be switched off by the user.",
    source: APPENDIX_A,
  },
  {
    id: "MAN-009",
    group: ABUSE,
    title: "Payments: button disabled after first click, idempotency keys, fulfilment only after webhook",
    howToTest:
      "Double-click the pay button, then check that only one charge was created. Confirm orders are fulfilled from the payment provider's webhook, not from the success page.",
    why: "Success pages can be visited without paying, and double submissions can charge customers twice.",
    source: APPENDIX_A,
  },
  {
    id: "MAN-010",
    group: AUTH,
    title: "Email verification on; generic 'invalid credentials' login errors",
    howToTest:
      "Sign up with an address you don't control and see if you get in. Try logging in with a wrong password for a real and a fake email: the messages should be identical.",
    why: "Different error messages let attackers find which emails have accounts, and unverified emails enable impersonation.",
    source: APPENDIX_A,
  },
  {
    id: "MAN-011",
    group: AUTH,
    title: "Proven auth provider or library; no home-made auth",
    howToTest:
      "Check where sign-in, sessions and password hashing come from. They should come from a maintained provider or library.",
    why: "Home-made authentication is easy to get subtly wrong, and the mistakes are invisible until exploited.",
    source: APPENDIX_A,
  },
  {
    id: "MAN-012",
    group: AUTH,
    title: "Server-side input validation, length limits, upload type and size limits",
    howToTest:
      "Send an oversized value, a wrong type, and a large or mislabeled file to each form's API. The server should reject them.",
    why: "Front-end validation is a convenience for users; only server-side validation protects your data and storage bill.",
    source: APPENDIX_A,
  },
  {
    id: "MAN-013",
    group: AUTH,
    title: "Storage buckets private; EXIF stripped from uploaded photos",
    howToTest:
      "Open an uploaded file's URL in a private window. Download an uploaded photo and check it has no GPS location in its metadata.",
    why: "Public buckets expose every user's files, and photo metadata can reveal where people live.",
    source: APPENDIX_A,
  },
  {
    id: "MAN-014",
    group: OPS,
    title: "Separate dev and prod databases; backups enabled; agents have no prod access",
    howToTest:
      "Confirm your local .env points at a dev project, that backups are on for production, and that no AI agent or script holds production credentials.",
    why: "One mistaken command against production can delete real users' data with no way back.",
    source: APPENDIX_A,
  },
  {
    id: "MAN-015",
    group: OPS,
    title: "Any key ever exposed (chat, screenshot, commit) has been rotated",
    howToTest:
      "List every key you've pasted into a chat, shown in a screenshot or committed. Rotate each one in the provider's dashboard.",
    why: "Deleting a key from code doesn't un-leak it. Only rotation makes the old value useless.",
    source: APPENDIX_A,
  },
  {
    id: "MAN-016",
    group: OPS,
    title: "Threat model written",
    howToTest:
      "Write one page answering: what are we building, what can go wrong, what are we doing about it, and did we do a good job?",
    why: "Thinking like an attacker for half an hour finds problems no scanner can, because they depend on your business logic.",
    source: APPENDIX_A,
  },
  {
    id: "MAN-017",
    group: AUTH,
    title: "Automated test proving user B can't read or modify user A's data",
    howToTest:
      "Add a test that signs in as two users and asserts that B's reads and writes of A's records fail. Run it in CI.",
    why: "Access rules regress silently when tables or policies change. A test catches it before users do.",
    source: APPENDIX_A,
  },
  {
    id: "MAN-018",
    group: OPS,
    title: "Error tracking and logging with retention; no sensitive data in logs or errors",
    howToTest:
      "Trigger an error and check that it reaches your error tracker, that logs are kept for a set time, and that neither contains passwords, tokens or personal data.",
    why: "You can't respond to attacks you can't see, and logs full of secrets become a second leak.",
    source: APPENDIX_A,
  },
];
