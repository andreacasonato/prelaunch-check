import { describe, expect, it } from "vitest";
import { readYamlOutline } from "../src/util/yaml-outline.js";

const wf = `name: CI # trailing comment
on:
  pull_request_target:
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - name: "Greet"
        run: |
          echo "hi # not a comment"
          echo done
      - run: echo "one line"
`;

describe("readYamlOutline", () => {
  const entries = readYamlOutline(wf);
  const find = (key: string) => entries.filter((e) => e.key === key);

  it("reads keys, values, lines and ancestry", () => {
    expect(find("name")[0]).toMatchObject({ value: "CI", line: 1, path: [] });
    expect(find("contents")[0]).toMatchObject({ value: "read", path: ["permissions"] });
    expect(find("uses")[0]).toMatchObject({
      value: "actions/checkout@v4",
      line: 10,
      path: ["jobs", "build", "steps", "-"],
    });
    expect(find("ref")[0]).toMatchObject({ path: ["jobs", "build", "steps", "-", "with"] });
  });

  it("groups keys of the same sequence item", () => {
    expect(find("ref")[0]!.itemId).toBe(find("uses")[0]!.itemId);
    expect(find("run")[0]!.itemId).not.toBe(find("uses")[0]!.itemId);
  });

  it("reads block scalars and keeps # inside strings", () => {
    const run = find("run");
    expect(run[0]!.block).toBe('echo "hi # not a comment"\necho done');
    expect(run[1]!.value).toBe('echo "one line"');
  });

  it("reads empty-valued keys", () => {
    expect(find("pull_request_target")[0]).toMatchObject({ value: "", path: ["on"] });
  });
});
