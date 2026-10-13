// DB-003 "money or power" column names (docs/02-TRD.md §6.2). Extend via config `sensitiveColumnNames`.
// "*" is a wildcard: "subscription*" matches subscription_status, "*_limit" matches daily_limit.
export const SENSITIVE_COLUMNS: readonly string[] = [
  "role",
  "is_admin",
  "admin",
  "plan",
  "tier",
  "subscription*",
  "credits",
  "balance",
  "quota",
  "*_limit",
  "usage*",
  "trial_end*",
  "is_premium",
  "premium",
  "paid",
  "stripe_customer_id",
];

export function sensitiveMatcher(extra: readonly string[]): (column: string) => boolean {
  const res = [...SENSITIVE_COLUMNS, ...extra].map(
    (p) =>
      new RegExp(
        `^${p
          .toLowerCase()
          .replace(/[.+?^${}()|[\]\\]/g, "\\$&")
          .replace(/\*/g, "[a-z0-9_]*")}$`,
      ),
  );
  return (column) => res.some((re) => re.test(column.toLowerCase()));
}
