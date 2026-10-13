// Hash routing (TRD §11): deep links work on static hosting without server rewrites.
import { useEffect, useState } from "react";

export function currentRoute(): string {
  const h = typeof location === "undefined" ? "" : location.hash.replace(/^#/, "");
  return h.startsWith("/") ? h : "/";
}

export function useRoute(): string {
  const [route, setRoute] = useState(currentRoute);
  useEffect(() => {
    const on = () => setRoute(currentRoute());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return route;
}

export function navigate(path: string): void {
  if (currentRoute() === path) return;
  location.hash = path;
}

export function findingPath(fingerprint: string): string {
  return `/finding/${encodeURIComponent(fingerprint)}`;
}
