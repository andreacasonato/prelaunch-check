/** Truncates in the middle so the file name and line stay visible: src/…/route.ts:42 */
export function truncateMiddle(s: string, n: number): string {
  if (s.length <= n) return s;
  const keep = n - 1;
  const tail = Math.ceil(keep * 0.6);
  return `${s.slice(0, keep - tail)}…${s.slice(s.length - tail)}`;
}
