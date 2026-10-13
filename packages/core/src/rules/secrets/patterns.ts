// Secret-key patterns (docs/02-TRD.md §6.1). Never hand-invent vendor regexes:
// - Stripe and Supabase prefixes come from the vendors' own docs (cited per entry).
// - Every other pattern is ported from gitleaks' default config (MIT, see NOTICE),
//   gitleaks v8.30.1, config/gitleaks.toml. Go/RE2-only syntax is translated to an
//   equivalent JS form, noted per entry. Group 1 is always the secret.
import type { Severity } from "../../types.js";

export type PatternKind = "secret" | "publishable";

export interface SecretPattern {
  id: string;
  vendor: string;
  /** Human label used in titles, e.g. "Stripe secret key". */
  label: string;
  kind: PatternKind;
  regex: RegExp;
  /** Lower-case strings; at least one must appear in the text before the regex runs (as in gitleaks). */
  keywords: string[];
  severity: Severity;
  isTest: boolean;
  /** Minimum Shannon entropy of the secret (gitleaks semantics: must be strictly greater). */
  entropy?: number;
  /** Values matching any of these are ignored (gitleaks per-rule allowlists). */
  allow?: RegExp[];
  source: string;
  sourceUrl: string;
}

const GITLEAKS = "gitleaks default config (MIT)";
const GITLEAKS_URL = "https://github.com/gitleaks/gitleaks/blob/v8.30.1/config/gitleaks.toml";
const STRIPE_DOCS = "https://docs.stripe.com/keys";
const SUPABASE_DOCS = "https://supabase.com/docs/guides/api/api-keys";

/** gitleaks' common terminator: a quote, backtick, whitespace, ;, an escaped \n/\r, or end of input. */
const END = String.raw`(?:[\x60'"\s;]|\\[nr]|$)`;

function re(source: string, flags = ""): RegExp {
  return new RegExp(source, `g${flags}`);
}

export const SECRET_PATTERNS: readonly SecretPattern[] = [
  // --- Stripe. Prefixes per Stripe docs: sk_/rk_ are secret and restricted keys, *_test_ are test mode.
  // Body charset and length from gitleaks "stripe-access-token", split into live and test variants.
  {
    id: "stripe-secret-live",
    vendor: "Stripe",
    label: "Stripe live secret key",
    kind: "secret",
    regex: re(String.raw`\b((?:sk|rk)_(?:live|prod)_[a-zA-Z0-9]{10,99})${END}`),
    keywords: ["sk_live", "sk_prod", "rk_live", "rk_prod"],
    severity: "critical",
    isTest: false,
    entropy: 2,
    source: `Stripe API keys docs (prefixes); ${GITLEAKS} stripe-access-token (body)`,
    sourceUrl: STRIPE_DOCS,
  },
  {
    id: "stripe-secret-test",
    vendor: "Stripe",
    label: "Stripe test secret key",
    kind: "secret",
    regex: re(String.raw`\b((?:sk|rk)_test_[a-zA-Z0-9]{10,99})${END}`),
    keywords: ["sk_test", "rk_test"],
    severity: "medium",
    isTest: true,
    entropy: 2,
    source: `Stripe API keys docs (prefixes); ${GITLEAKS} stripe-access-token (body)`,
    sourceUrl: STRIPE_DOCS,
  },
  // --- Supabase. Prefix per Supabase docs ("sb_secret_..."). Supabase documents no length or
  // charset, so the body is a conservative URL-safe token of 16+ characters (Decision).
  {
    id: "supabase-secret",
    vendor: "Supabase",
    label: "Supabase secret key",
    kind: "secret",
    regex: re(String.raw`(?<![A-Za-z0-9_-])(sb_secret_[A-Za-z0-9_-]{16,128})(?![A-Za-z0-9_-])`),
    keywords: ["sb_secret_"],
    severity: "critical",
    isTest: false,
    source: "Supabase API keys docs (prefix); body length is a Decision",
    sourceUrl: SUPABASE_DOCS,
  },
  // --- Ported from gitleaks.
  {
    id: "anthropic-api-key",
    vendor: "Anthropic",
    label: "Anthropic API key",
    kind: "secret",
    regex: re(String.raw`\b(sk-ant-api03-[a-zA-Z0-9_\-]{93}AA)${END}`),
    keywords: ["sk-ant-api03"],
    severity: "critical",
    isTest: false,
    source: `${GITLEAKS} anthropic-api-key`,
    sourceUrl: GITLEAKS_URL,
  },
  {
    id: "anthropic-admin-api-key",
    vendor: "Anthropic",
    label: "Anthropic admin API key",
    kind: "secret",
    regex: re(String.raw`\b(sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA)${END}`),
    keywords: ["sk-ant-admin01"],
    severity: "critical",
    isTest: false,
    source: `${GITLEAKS} anthropic-admin-api-key`,
    sourceUrl: GITLEAKS_URL,
  },
  {
    id: "openai-api-key",
    vendor: "OpenAI",
    label: "OpenAI API key",
    kind: "secret",
    regex: re(
      String.raw`\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})\b|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})${END}`,
    ),
    keywords: ["t3blbkfj"],
    severity: "critical",
    isTest: false,
    entropy: 3,
    source: `${GITLEAKS} openai-api-key`,
    sourceUrl: GITLEAKS_URL,
  },
  {
    id: "aws-access-token",
    vendor: "AWS",
    label: "AWS access key ID",
    kind: "secret",
    regex: re(String.raw`\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b`),
    keywords: ["a3t", "akia", "asia", "abia", "acca"],
    severity: "critical",
    isTest: false,
    entropy: 3,
    allow: [/.+EXAMPLE$/],
    source: `${GITLEAKS} aws-access-token`,
    sourceUrl: GITLEAKS_URL,
  },
  {
    id: "github-pat",
    vendor: "GitHub",
    label: "GitHub personal access token",
    kind: "secret",
    regex: re(String.raw`(ghp_[0-9a-zA-Z]{36})`),
    keywords: ["ghp_"],
    severity: "critical",
    isTest: false,
    entropy: 3,
    source: `${GITLEAKS} github-pat`,
    sourceUrl: GITLEAKS_URL,
  },
  {
    id: "github-fine-grained-pat",
    vendor: "GitHub",
    label: "GitHub fine-grained personal access token",
    kind: "secret",
    regex: re(String.raw`(github_pat_\w{82})`),
    keywords: ["github_pat_"],
    severity: "critical",
    isTest: false,
    entropy: 3,
    source: `${GITLEAKS} github-fine-grained-pat`,
    sourceUrl: GITLEAKS_URL,
  },
  {
    id: "github-oauth",
    vendor: "GitHub",
    label: "GitHub OAuth access token",
    kind: "secret",
    regex: re(String.raw`(gho_[0-9a-zA-Z]{36})`),
    keywords: ["gho_"],
    severity: "critical",
    isTest: false,
    entropy: 3,
    source: `${GITLEAKS} github-oauth`,
    sourceUrl: GITLEAKS_URL,
  },
  {
    id: "github-app-token",
    vendor: "GitHub",
    label: "GitHub app token",
    kind: "secret",
    regex: re(String.raw`((?:ghu|ghs)_[0-9a-zA-Z]{36})`),
    keywords: ["ghu_", "ghs_"],
    severity: "critical",
    isTest: false,
    entropy: 3,
    source: `${GITLEAKS} github-app-token`,
    sourceUrl: GITLEAKS_URL,
  },
  {
    id: "github-refresh-token",
    vendor: "GitHub",
    label: "GitHub refresh token",
    kind: "secret",
    regex: re(String.raw`(ghr_[0-9a-zA-Z]{36})`),
    keywords: ["ghr_"],
    severity: "critical",
    isTest: false,
    entropy: 3,
    source: `${GITLEAKS} github-refresh-token`,
    sourceUrl: GITLEAKS_URL,
  },
  {
    id: "gitlab-pat",
    vendor: "GitLab",
    label: "GitLab personal access token",
    kind: "secret",
    regex: re(String.raw`(glpat-[\w-]{20})`),
    keywords: ["glpat-"],
    severity: "critical",
    isTest: false,
    entropy: 3,
    source: `${GITLEAKS} gitlab-pat`,
    sourceUrl: GITLEAKS_URL,
  },
  {
    id: "slack-bot-token",
    vendor: "Slack",
    label: "Slack bot token",
    kind: "secret",
    regex: re(String.raw`(xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)`),
    keywords: ["xoxb"],
    severity: "critical",
    isTest: false,
    entropy: 3,
    source: `${GITLEAKS} slack-bot-token`,
    sourceUrl: GITLEAKS_URL,
  },
  {
    id: "slack-user-token",
    vendor: "Slack",
    label: "Slack user token",
    kind: "secret",
    regex: re(String.raw`(xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34})`),
    keywords: ["xoxp-", "xoxe-"],
    severity: "critical",
    isTest: false,
    entropy: 2,
    source: `${GITLEAKS} slack-user-token`,
    sourceUrl: GITLEAKS_URL,
  },
  {
    id: "slack-app-token",
    vendor: "Slack",
    label: "Slack app token",
    kind: "secret",
    // gitleaks: (?i) applies to the whole pattern → JS "i" flag.
    regex: re(String.raw`(xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+)`, "i"),
    keywords: ["xapp"],
    severity: "critical",
    isTest: false,
    entropy: 2,
    source: `${GITLEAKS} slack-app-token`,
    sourceUrl: GITLEAKS_URL,
  },
  {
    id: "slack-webhook-url",
    vendor: "Slack",
    label: "Slack incoming webhook URL",
    kind: "secret",
    regex: re(
      String.raw`((?:https?://)?hooks.slack.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56})`,
    ),
    keywords: ["hooks.slack.com"],
    severity: "high",
    isTest: false,
    source: `${GITLEAKS} slack-webhook-url`,
    sourceUrl: GITLEAKS_URL,
  },
  {
    id: "sendgrid-api-token",
    vendor: "SendGrid",
    label: "SendGrid API key",
    kind: "secret",
    // gitleaks: SG\.(?i)[a-z0-9=_\-\.]{66} → case-insensitive class written out.
    regex: re(String.raw`\b(SG\.[a-zA-Z0-9=_\-.]{66})${END}`),
    keywords: ["sg."],
    severity: "critical",
    isTest: false,
    entropy: 2,
    source: `${GITLEAKS} sendgrid-api-token`,
    sourceUrl: GITLEAKS_URL,
  },
  {
    id: "twilio-api-key",
    vendor: "Twilio",
    label: "Twilio API key",
    kind: "secret",
    regex: re(String.raw`(SK[0-9a-fA-F]{32})`),
    keywords: ["sk"],
    severity: "critical",
    isTest: false,
    entropy: 3,
    source: `${GITLEAKS} twilio-api-key`,
    sourceUrl: GITLEAKS_URL,
  },
  {
    id: "npm-access-token",
    vendor: "npm",
    label: "npm access token",
    kind: "secret",
    regex: re(String.raw`\b(npm_[a-z0-9]{36})${END}`, "i"),
    keywords: ["npm_"],
    severity: "critical",
    isTest: false,
    entropy: 2,
    source: `${GITLEAKS} npm-access-token`,
    sourceUrl: GITLEAKS_URL,
  },
  {
    id: "pypi-upload-token",
    vendor: "PyPI",
    label: "PyPI upload token",
    kind: "secret",
    regex: re(String.raw`(pypi-AgEIcHlwaS5vcmc[\w-]{50,1000})`),
    keywords: ["pypi-ageichlwas5vcmc"],
    severity: "critical",
    isTest: false,
    entropy: 3,
    source: `${GITLEAKS} pypi-upload-token`,
    sourceUrl: GITLEAKS_URL,
  },
  {
    id: "huggingface-access-token",
    vendor: "Hugging Face",
    label: "Hugging Face access token",
    kind: "secret",
    // gitleaks: hf_(?i:[a-z]{34}) → [a-zA-Z]{34}.
    regex: re(String.raw`\b(hf_[a-zA-Z]{34})${END}`),
    keywords: ["hf_"],
    severity: "critical",
    isTest: false,
    entropy: 2,
    source: `${GITLEAKS} huggingface-access-token`,
    sourceUrl: GITLEAKS_URL,
  },
  {
    id: "digitalocean-pat",
    vendor: "DigitalOcean",
    label: "DigitalOcean personal access token",
    kind: "secret",
    regex: re(String.raw`\b(dop_v1_[a-f0-9]{64})${END}`),
    keywords: ["dop_v1_"],
    severity: "critical",
    isTest: false,
    entropy: 3,
    source: `${GITLEAKS} digitalocean-pat`,
    sourceUrl: GITLEAKS_URL,
  },
  {
    id: "digitalocean-access-token",
    vendor: "DigitalOcean",
    label: "DigitalOcean OAuth access token",
    kind: "secret",
    regex: re(String.raw`\b(doo_v1_[a-f0-9]{64})${END}`),
    keywords: ["doo_v1_"],
    severity: "critical",
    isTest: false,
    entropy: 3,
    source: `${GITLEAKS} digitalocean-access-token`,
    sourceUrl: GITLEAKS_URL,
  },
  {
    id: "shopify-access-token",
    vendor: "Shopify",
    label: "Shopify access token",
    kind: "secret",
    regex: re(String.raw`(shp(?:at|ca|pa)_[a-fA-F0-9]{32})`),
    keywords: ["shpat_", "shpca_", "shppa_"],
    severity: "critical",
    isTest: false,
    entropy: 2,
    source: `${GITLEAKS} shopify-access-token, shopify-custom-access-token, shopify-private-app-access-token (merged)`,
    sourceUrl: GITLEAKS_URL,
  },
  {
    id: "linear-api-key",
    vendor: "Linear",
    label: "Linear API key",
    kind: "secret",
    // gitleaks: lin_api_(?i)[a-z0-9]{40} → [a-zA-Z0-9]{40}.
    regex: re(String.raw`(lin_api_[a-zA-Z0-9]{40})`),
    keywords: ["lin_api_"],
    severity: "critical",
    isTest: false,
    entropy: 2,
    source: `${GITLEAKS} linear-api-key`,
    sourceUrl: GITLEAKS_URL,
  },
  {
    id: "planetscale-password",
    vendor: "PlanetScale",
    label: "PlanetScale password",
    kind: "secret",
    regex: re(String.raw`\b(pscale_pw_[\w=.-]{32,64})${END}`, "i"),
    keywords: ["pscale_pw_"],
    severity: "critical",
    isTest: false,
    entropy: 3,
    source: `${GITLEAKS} planetscale-password`,
    sourceUrl: GITLEAKS_URL,
  },
  {
    id: "planetscale-api-token",
    vendor: "PlanetScale",
    label: "PlanetScale API token",
    kind: "secret",
    regex: re(String.raw`\b(pscale_tkn_[\w=.-]{32,64})${END}`),
    keywords: ["pscale_tkn_"],
    severity: "critical",
    isTest: false,
    entropy: 3,
    source: `${GITLEAKS} planetscale-api-token`,
    sourceUrl: GITLEAKS_URL,
  },
  {
    id: "doppler-api-token",
    vendor: "Doppler",
    label: "Doppler API token",
    kind: "secret",
    // gitleaks: dp\.pt\.(?i)[a-z0-9]{43} → [a-zA-Z0-9]{43}.
    regex: re(String.raw`(dp\.pt\.[a-zA-Z0-9]{43})`),
    keywords: ["dp.pt."],
    severity: "critical",
    isTest: false,
    entropy: 2,
    source: `${GITLEAKS} doppler-api-token`,
    sourceUrl: GITLEAKS_URL,
  },
  {
    id: "databricks-api-token",
    vendor: "Databricks",
    label: "Databricks API token",
    kind: "secret",
    regex: re(String.raw`\b(dapi[a-f0-9]{32}(?:-\d)?)${END}`),
    keywords: ["dapi"],
    severity: "critical",
    isTest: false,
    entropy: 3,
    source: `${GITLEAKS} databricks-api-token`,
    sourceUrl: GITLEAKS_URL,
  },
  {
    id: "perplexity-api-key",
    vendor: "Perplexity",
    label: "Perplexity API key",
    kind: "secret",
    regex: re(String.raw`\b(pplx-[a-zA-Z0-9]{48})(?:[\x60'"\s;]|\\[nr]|$|\b)`),
    keywords: ["pplx-"],
    severity: "critical",
    isTest: false,
    entropy: 4,
    source: `${GITLEAKS} perplexity-api-key`,
    sourceUrl: GITLEAKS_URL,
  },
];

/** Keys that are designed to be public. Reported as info (SEC-INFO-001) so users learn they're fine. */
export const PUBLISHABLE_PATTERNS: readonly SecretPattern[] = [
  {
    id: "stripe-publishable",
    vendor: "Stripe",
    label: "Stripe publishable key",
    kind: "publishable",
    // Prefix per Stripe docs ("publishable keys … safe to expose"); body as for secret keys.
    regex: re(String.raw`\b(pk_(?:live|test)_[a-zA-Z0-9]{10,99})${END}`),
    keywords: ["pk_live", "pk_test"],
    severity: "info",
    isTest: false,
    source: `Stripe API keys docs (prefix); ${GITLEAKS} stripe-access-token (body)`,
    sourceUrl: STRIPE_DOCS,
  },
  {
    id: "supabase-publishable",
    vendor: "Supabase",
    label: "Supabase publishable key",
    kind: "publishable",
    regex: re(String.raw`(?<![A-Za-z0-9_-])(sb_publishable_[A-Za-z0-9_-]{16,128})(?![A-Za-z0-9_-])`),
    keywords: ["sb_publishable_"],
    severity: "info",
    isTest: false,
    source: "Supabase API keys docs (prefix); body length is a Decision",
    sourceUrl: SUPABASE_DOCS,
  },
  {
    id: "google-api-key",
    vendor: "Firebase",
    label: "Firebase/Google API key",
    kind: "publishable",
    regex: re(String.raw`\b(AIza[\w-]{35})${END}`),
    keywords: ["aiza"],
    severity: "info",
    isTest: false,
    entropy: 4,
    source: `${GITLEAKS} gcp-api-key; Firebase API keys docs`,
    sourceUrl: "https://firebase.google.com/docs/projects/api-keys",
  },
];

/** Candidate JWTs (gitleaks "jwt" rule). Supabase legacy keys are classified by their role claim. */
export const JWT_REGEX = re(
  String.raw`\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/\\_-]{17,}\.(?:[a-zA-Z0-9\/\\_-]{10,}={0,2})?)${END}`,
);

/**
 * Placeholder values that are never real secrets (subset of gitleaks' global allowlist):
 * repeated single characters and template references like ${VAR}, {{ x }}, $VAR.
 */
export const GLOBAL_ALLOW: readonly RegExp[] = [
  /^(.)\1*$/,
  /^\$(?:\d+|\{\d+\})$/,
  /^\$(?:[A-Z_]+|[a-z_]+)$/,
  /^\$\{(?:[A-Z_]+|[a-z_]+)\}$/,
  /^\{\{[ \t]*[\w ().|]+[ \t]*\}\}$/,
];
