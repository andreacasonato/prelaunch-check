import { describe, expect, it } from "vitest";
import { TOOL_NAME } from "@prelaunch-check/core";

describe("cli", () => {
  it("resolves the core workspace package", () => {
    expect(TOOL_NAME).toBe("prelaunch-check");
  });
});
