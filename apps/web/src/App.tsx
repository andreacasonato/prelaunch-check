import { useEffect, useState } from "react";
import { Monitor, Moon, Sun } from "lucide-react";
import { useRoute } from "./lib/router";
import { getTheme, setTheme, type Theme } from "./lib/storage";
import { Home } from "./routes/Home";
import { Scan } from "./routes/Scan";
import { Report } from "./routes/Report";
import { Checklist } from "./routes/Checklist";
import { OpenReport } from "./routes/OpenReport";
import { LiveSite } from "./routes/LiveSite";
import { Docs } from "./routes/Docs";
import { REPO_URL } from "./lib/rules";

export function applyTheme(t: Theme): void {
  if (t === "system") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", t);
}

const NEXT_THEME: Record<Theme, Theme> = { system: "light", light: "dark", dark: "system" };
const THEME_LABEL: Record<Theme, string> = {
  system: "Theme: system",
  light: "Theme: light",
  dark: "Theme: dark",
};

function ThemeToggle() {
  const [theme, set] = useState<Theme>(getTheme);
  const Icon = theme === "light" ? Sun : theme === "dark" ? Moon : Monitor;
  return (
    <button
      type="button"
      className="btn btn-quiet"
      onClick={() => {
        const n = NEXT_THEME[theme];
        set(n);
        setTheme(n);
        applyTheme(n);
      }}
      aria-label={`${THEME_LABEL[theme]}. Change theme`}
    >
      <Icon size={16} aria-hidden />
      <span className="small">{THEME_LABEL[theme]}</span>
    </button>
  );
}

const NAV = [
  { href: "/scan", label: "Scan" },
  { href: "/report", label: "Report" },
  { href: "/checklist", label: "Checklist" },
  { href: "/open", label: "Open a report" },
  { href: "/live", label: "Live site" },
  { href: "/docs", label: "Docs" },
];

function Page({ route }: { route: string }) {
  if (route === "/") return <Home />;
  if (route === "/scan") return <Scan />;
  if (route === "/report" || route === "/export") return <Report />;
  if (route.startsWith("/finding/"))
    return <Report fingerprint={decodeURIComponent(route.slice("/finding/".length))} />;
  if (route === "/checklist") return <Checklist />;
  if (route === "/open") return <OpenReport />;
  if (route === "/live") return <LiveSite />;
  if (route.startsWith("/docs")) return <Docs route={route} />;
  return (
    <>
      <h1>Page not found</h1>
      <p>
        <a href="#/">Go to the home page</a>
      </p>
    </>
  );
}

export function App() {
  const route = useRoute();
  useEffect(() => {
    if (!route.startsWith("/finding/")) window.scrollTo(0, 0);
    const h1 = document.querySelector("main h1");
    document.title = h1?.textContent ? `${h1.textContent} · Prelaunch Check` : "Prelaunch Check";
  }, [route]);
  const section = "/" + (route.split("/")[1] ?? "");
  return (
    <>
      <a
        className="skip-link"
        href="#main"
        onClick={(e) => {
          e.preventDefault();
          document.getElementById("main")?.focus();
        }}
      >
        Skip to content
      </a>
      <header className="site-header">
        <a className="brand" href="#/">
          Prelaunch Check
        </a>
        <nav className="site-nav" aria-label="Main">
          <ul>
            {NAV.map((n) => (
              <li key={n.href}>
                <a
                  href={`#${n.href}`}
                  aria-current={
                    section === n.href || (n.href === "/report" && section === "/finding")
                      ? "page"
                      : undefined
                  }
                >
                  {n.label}
                </a>
              </li>
            ))}
          </ul>
        </nav>
        <ThemeToggle />
      </header>
      <main id="main" tabIndex={-1}>
        <Page route={route} />
      </main>
      <footer className="site-footer">
        <ul>
          <li>
            <a href="#/docs/privacy">Privacy</a>
          </li>
          <li>
            <a href="#/docs/scoring">How scoring works</a>
          </li>
          <li>
            <a href="#/docs/about">About &amp; limitations</a>
          </li>
          <li>
            <a href={REPO_URL}>Source code</a>
          </li>
        </ul>
        <p>No AI. No account. No upload. Prelaunch Check {__APP_VERSION__}, MIT license.</p>
      </footer>
    </>
  );
}
