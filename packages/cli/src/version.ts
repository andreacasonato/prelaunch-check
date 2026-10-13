declare const __TOOL_VERSION__: string | undefined;

/** Injected at build time from package.json; "0.0.0-dev" when running from source. */
export const VERSION = typeof __TOOL_VERSION__ === "string" ? __TOOL_VERSION__ : "0.0.0-dev";
export const USER_AGENT = `prelaunch-check/${VERSION} (+https://github.com/andreacasonato/prelaunch-check)`;
export const WEB_APP_URL = "https://andreacasonato.github.io/prelaunch-check/";
