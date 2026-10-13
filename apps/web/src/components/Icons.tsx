// Severity and verdict icons (Design Brief §4.3): shape + label + colour, never colour alone.
import {
  Check,
  CircleAlert,
  CircleCheck,
  CircleHelp,
  Info,
  Octagon,
  OctagonAlert,
  TriangleAlert,
} from "lucide-react";
import type { Confidence, Severity, Verdict } from "@prelaunch-check/core";

export const SEVERITY_WORD: Record<Severity | "worth", string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
  worth: "Worth checking",
};

export function sevKey(severity: Severity, confidence: Confidence = "high"): Severity | "worth" {
  return confidence === "low" ? "worth" : severity;
}

export function SeverityIcon({ level, size = 16 }: { level: Severity | "worth"; size?: number }) {
  const props = { size, "aria-hidden": true, focusable: false, strokeWidth: 2 } as const;
  switch (level) {
    case "critical":
      return <OctagonAlert {...props} />;
    case "high":
      return <TriangleAlert {...props} />;
    case "medium":
      return <CircleAlert {...props} />;
    case "low":
      return <Info {...props} />;
    case "info":
      return <Info {...props} />;
    case "worth":
      return <CircleHelp {...props} strokeDasharray="3 2" />;
  }
}

export function SeverityBadge({ severity, confidence }: { severity: Severity; confidence?: Confidence }) {
  const level = sevKey(severity, confidence);
  return (
    <span className={`sev badge sev-${level}`}>
      <SeverityIcon level={level} />
      {SEVERITY_WORD[level]}
    </span>
  );
}

export function VerdictIcon({ verdict, size = 32 }: { verdict: Verdict; size?: number }) {
  const props = { size, "aria-hidden": true, focusable: false, className: "verdict-icon" } as const;
  if (verdict === "blocked") return <Octagon {...props} />;
  if (verdict === "needs_attention") return <TriangleAlert {...props} />;
  return <CircleCheck {...props} />;
}

export { Check };
