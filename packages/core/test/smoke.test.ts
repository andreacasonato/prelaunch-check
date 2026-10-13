import { describe, expect, it } from "vitest";
import { TOOL_NAME } from "../src/index.js";

describe("core", () => {
  it("exports the tool name", () => {
    expect(TOOL_NAME).toBe("prelaunch-check");
  });
});
