import type { Rule } from "@prelaunch-check/core";

export function rulesText(rules: readonly Rule[]): string {
  const lines = rules.map(
    (r) => `${r.meta.id.padEnd(13)} ${r.meta.severity.toUpperCase().padEnd(9)} ${r.meta.title}`,
  );
  return [`${"ID".padEnd(13)} ${"SEVERITY".padEnd(9)} TITLE`, ...lines].join("\n") + "\n";
}

export function rulesJson(rules: readonly Rule[]): string {
  // appliesWhen is a function; everything else is plain data.
  return (
    JSON.stringify(
      rules.map(({ meta: { appliesWhen: _a, ...meta } }) => meta),
      null,
      2,
    ) + "\n"
  );
}
