import { TOOL_NAME } from "@prelaunch-check/core";

declare const __TOOL_VERSION__: string | undefined;
export const VERSION = typeof __TOOL_VERSION__ === "string" ? __TOOL_VERSION__ : "0.0.0-dev";

console.log(`${TOOL_NAME} ${VERSION}`);
