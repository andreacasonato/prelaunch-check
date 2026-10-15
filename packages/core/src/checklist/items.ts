// Manual checklist MAN-001…031 (TRD §6.7). Data only: never affects the score.
import type { ChecklistGroup, ChecklistItem, ChecklistLink } from "../types.js";

const APPENDIX_A = "Creating a Secure App — Appendix A: Master Security & Launch Checklist";
const VERIFY = "Creating a Secure App — Verify: Hack Yourself Before Someone Else Does";

const BREAK_IN = "Try to break in";
const ABUSE = "Abuse & cost";
const AUTH = "Auth & data";
const OPS = "Operations";
const LEGAL = "Legal & trust";

export const CHECKLIST_GROUPS: readonly ChecklistGroup[] = [
  { title: BREAK_IN },
  { title: ABUSE },
  { title: AUTH },
  { title: OPS },
  {
    title: LEGAL,
    intro:
      "Common legal and trust problems for apps that take sign-ups or payments. This isn't legal advice, and no scanner can check these for you. What applies depends on where you are and where your users are. If you handle health, money or children's data, talk to a lawyer. Last reviewed October 2026.",
  },
];

// Legal items cite regulators, not the book. Each link was checked when the item was written.
const GDPR = (article: string): ChecklistLink => ({
  label: `EU GDPR ${article}`,
  url: "https://eur-lex.europa.eu/eli/reg/2016/679/oj",
});

function legal(item: Omit<ChecklistItem, "group" | "source"> & { links: ChecklistLink[] }): ChecklistItem {
  return { ...item, group: LEGAL, source: item.links.map((l) => l.label).join("; ") };
}

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
  legal({
    id: "MAN-019",
    title: "A privacy policy is published and matches what the app actually collects",
    howToTest:
      "List every field you store and every third-party SDK or script (analytics, payments, error tracking, AI APIs). Check that each one appears in your privacy policy with what it's for, and that the policy is linked from the footer and the sign-up form.",
    why: "Privacy laws require you to tell people what you collect, why, and who receives it. A copied template that doesn't mention your actual tools is a common complaint.",
    links: [
      GDPR("Art. 13"),
      {
        label: "ICO: right to be informed",
        url: "https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/individual-rights/right-to-be-informed/",
      },
      { label: "California CCPA", url: "https://oag.ca.gov/privacy/ccpa" },
    ],
  }),
  legal({
    id: "MAN-020",
    title: "You collect only data the app actually uses",
    howToTest:
      'Go through your sign-up and profile forms and your database tables. For each field, name the feature that needs it. Remove anything you can\'t name a feature for, such as a birthday or phone number kept "for later".',
    why: "Data you don't collect can't leak and doesn't need explaining. GDPR calls this data minimisation.",
    links: [GDPR("Art. 5(1)(c)")],
  }),
  legal({
    id: "MAN-021",
    title:
      "Non-essential cookies and trackers load only after consent, and rejecting is as easy as accepting",
    howToTest:
      "Open the site in a private window and don't touch the banner. In DevTools, check Application → Cookies and the Network tab: no analytics or ad cookies or requests yet. Then check that rejecting takes one click, like accepting.",
    why: "In the EU, analytics and advertising cookies need consent first. Since 2026 the UK lets some low-risk analytics run without it, but advertising and cross-site tracking still need consent.",
    links: [
      {
        label: "EDPB Guidelines 05/2020 on consent",
        url: "https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-052020-consent-under-regulation-2016679_en",
      },
      {
        label: "ICO: storage and access technologies",
        url: "https://ico.org.uk/for-organisations/direct-marketing-and-privacy-and-electronic-communications/guidance-on-the-use-of-storage-and-access-technologies/about-this-guidance/",
      },
    ],
  }),
  legal({
    id: "MAN-022",
    title: "Consent checkboxes start unticked and are separate from accepting the terms",
    howToTest:
      "Look at every form that asks for consent (newsletter, marketing, data sharing). Each one has its own checkbox, unticked by default, and the form still submits without it.",
    why: "The EU Court of Justice ruled that a pre-ticked box isn't valid consent.",
    links: [{ label: "CJEU C-673/17 Planet49", url: "https://curia.europa.eu/juris/liste.jsf?num=C-673/17" }],
  }),
  legal({
    id: "MAN-023",
    title: "Terms of service and a refund policy are published and match how you charge",
    howToTest:
      "Read your terms and refund policy next to your pricing page and checkout. Plan names, prices, renewal periods and the refund window should all match. If you sell to EU consumers, check how you handle their 14-day right to withdraw.",
    why: "Customers and payment providers use these pages to settle disputes. If they contradict your checkout, you are the one who has to explain it.",
    links: [
      {
        label: "Your Europe: returns and the 14-day withdrawal right",
        url: "https://europa.eu/youreurope/citizens/consumers/shopping/returns/index_en.htm",
      },
    ],
  }),
  legal({
    id: "MAN-024",
    title:
      "The full price is shown before payment, with no pre-ticked extras, and cancelling is no harder than signing up",
    howToTest:
      "Go through checkout as a new user. The total you see before paying is what you're charged. Then cancel a subscription and count the steps compared with signing up.",
    why: "Hidden fees, pre-selected extras and hard-to-find cancellation are standard examples of dark patterns that regulators act on.",
    links: [
      {
        label: "FTC: Bringing Dark Patterns to Light (2022)",
        url: "https://www.ftc.gov/system/files/ftc_gov/pdf/P214800+Dark+Patterns+Report+9.14.2022+-+FINAL.pdf",
      },
    ],
  }),
  legal({
    id: "MAN-025",
    title: "Every review and testimonial comes from a real customer, and insider reviews are labelled",
    howToTest:
      "For each review, testimonial and customer logo on the site, check you could show where it came from. Remove placeholder or AI-written ones. Label reviews from staff, friends or anyone you paid.",
    why: "In the US, fake reviews and undisclosed insider reviews are banned by an FTC rule with civil penalties.",
    links: [
      {
        label: "FTC: Consumer Reviews and Testimonials Rule Q&A",
        url: "https://www.ftc.gov/business-guidance/resources/consumer-reviews-testimonials-rule-questions-answers",
      },
    ],
  }),
  legal({
    id: "MAN-026",
    title: "Every claim on the site can be backed up",
    howToTest:
      'List the factual claims on your landing page ("10,000 users", "#1", "bank-grade security", "saves 5 hours a week", "GDPR compliant"). For each one, write down the evidence you have today. Remove or reword any you can\'t back up.',
    why: "US law expects you to have the evidence before you make a claim, not after someone challenges it.",
    links: [
      {
        label: "FTC: Advertising FAQs for small business",
        url: "https://www.ftc.gov/business-guidance/resources/advertising-faqs-guide-small-business",
      },
    ],
  }),
  legal({
    id: "MAN-027",
    title: "Basic accessibility: alt text, readable contrast, keyboard navigation",
    howToTest:
      "Use the whole app with only the keyboard (Tab, Enter, Esc) and check you can always see where focus is. Run Lighthouse or axe DevTools on your main pages and fix the contrast and missing-alt-text warnings.",
    why: "Website accessibility lawsuits are common in the US. In the EU, the European Accessibility Act has applied since 28 June 2025; service businesses with fewer than 10 staff and at most €2M turnover are exempt.",
    links: [
      { label: "W3C: Easy checks", url: "https://www.w3.org/WAI/test-evaluate/preliminary/" },
      { label: "WCAG 2.2", url: "https://www.w3.org/TR/WCAG22/" },
      { label: "Directive (EU) 2019/882", url: "https://eur-lex.europa.eu/eli/dir/2019/882/oj" },
      { label: "ADA.gov web guidance", url: "https://www.ada.gov/resources/web-guidance/" },
    ],
  }),
  legal({
    id: "MAN-028",
    title: "Your business name and a way to contact you are easy to find",
    howToTest:
      "Check that the footer or a contact page shows who runs the app (legal name), a postal or registered address and a working email address.",
    why: "EU law requires online services to show who runs them and how to reach them. Some countries require a dedicated page, such as Germany's Impressum.",
    links: [
      {
        label: "E-Commerce Directive 2000/31/EC Art. 5",
        url: "https://eur-lex.europa.eu/eli/dir/2000/31/oj",
      },
    ],
  }),
  legal({
    id: "MAN-029",
    title: "You know whether children use the app, and handle their data accordingly",
    howToTest:
      "Decide whether the app is aimed at, or likely to attract, children under 13 (US) or under 16 (EU; the age varies by country). If so, check how you get parental consent. If not, say so in your terms and don't market to children.",
    why: "Children's data has the strictest rules: COPPA in the US, GDPR Art. 8 in the EU and the UK Children's code.",
    links: [
      {
        label: "FTC: Complying with COPPA FAQ",
        url: "https://www.ftc.gov/business-guidance/resources/complying-coppa-frequently-asked-questions",
      },
      GDPR("Art. 8"),
      {
        label: "ICO: Children's code",
        url: "https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/childrens-information/childrens-code-guidance-and-resources/",
      },
    ],
  }),
  legal({
    id: "MAN-030",
    title: "Marketing emails have a working unsubscribe link and your postal address",
    howToTest:
      "Send yourself each marketing email. Unsubscribe and confirm it works without logging in and that no more emails arrive. Check the footer shows a physical postal address.",
    why: "US law requires a clear opt-out, honoured within 10 business days, and a valid postal address in every commercial email.",
    links: [
      {
        label: "FTC: CAN-SPAM compliance guide",
        url: "https://www.ftc.gov/business-guidance/resources/can-spam-act-compliance-guide-business",
      },
    ],
  }),
  legal({
    id: "MAN-031",
    title: "Users can delete their account and data themselves",
    howToTest:
      "Create a test account, add some data, then delete the account from inside the app. Confirm the data is gone from your database and from services you sent it to (email list, analytics), not just hidden.",
    why: "GDPR and the CCPA give users a right to deletion. Apple and Google require in-app account deletion for apps that let users sign up, and Google also requires a web link for deletion requests.",
    links: [
      GDPR("Art. 17"),
      {
        label: "App Store Review Guideline 5.1.1(v)",
        url: "https://developer.apple.com/app-store/review/guidelines/",
      },
      {
        label: "Google Play: account deletion",
        url: "https://support.google.com/googleplay/android-developer/answer/13327111",
      },
    ],
  }),
];
