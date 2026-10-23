import { describe, expect, it } from "vitest";
import { mask, normalizePath, parseSarif, SarifError } from "./sarif.ts";
import { sarif, type TestResult } from "./test-app.ts";

const parse = (salt: string, ...r: TestResult[]) => parseSarif(JSON.parse(sarif(...r)), salt);
const key = "AKIAIOSFODNN7EXAMPLE";

describe("parseSarif", () => {
  it("reads rule, place and message, and keeps nothing of the match", () => {
    const { tool, findings } = parse("s", {
      rule: "aws-access-key",
      level: "warning",
      path: "src/deploy.sh",
      line: 7,
      code: `export KEY=${key}`,
      message: "Detected an AWS access key",
    });
    expect(tool).toBe("gitleaks");
    expect(findings).toEqual([
      {
        fingerprint: expect.stringMatching(/^[0-9a-f]{32}$/),
        ruleId: "aws-access-key",
        severity: "high",
        path: "src/deploy.sh",
        line: 7,
        message: "Detected an AWS access key",
      },
    ]);
    expect(JSON.stringify(findings)).not.toContain(key);
  });

  it("treats a warning as high, an error as critical, and honours security-severity", () => {
    const sev = (r: Omit<TestResult, "path">) => parse("s", { ...r, path: "a" }).findings[0]!.severity;
    expect(sev({ rule: "a" })).toBe("high");
    expect(sev({ rule: "a", level: "error" })).toBe("critical");
    expect(sev({ rule: "a", level: "note" })).toBe("medium");
    expect(sev({ rule: "a", score: 5 })).toBe("medium");
    expect(sev({ rule: "a", score: 2 })).toBe("low");
  });

  it("masks secrets a scanner puts in its message", () => {
    const { findings } = parse("s", { rule: "a", path: "a", message: `Found ${key} and token=abc123def and Bearer abcdefghijklmnop` });
    expect(findings[0]!.message).not.toMatch(/AKIA|abc123def|abcdefghijklmnop/);
    expect(findings[0]!.message.length).toBeLessThanOrEqual(300);
  });

  it("follows a secret when its line moves, and tells apart another secret in the same place", () => {
    const fp = (salt: string, line: number, code: string, path = "a.sh") => parse(salt, { rule: "r", path, line, code }).findings[0]!.fingerprint;
    expect(fp("s", 3, key)).toBe(fp("s", 90, key));
    expect(fp("s", 3, key)).not.toBe(fp("s", 3, "AKIAIOSFODNN7OTHER99"));
    expect(fp("s", 3, key)).not.toBe(fp("s", 3, key, "b.sh"));
    // The same secret has another fingerprint elsewhere, so a leaked fingerprint is no use on another installation.
    expect(fp("s", 3, key)).not.toBe(fp("other", 3, key));
    const twice = parse("s", { rule: "r", path: "a.sh", code: key }, { rule: "r", path: "a.sh", line: 9, code: key }).findings;
    expect(twice[1]!.fingerprint).toBe(`${twice[0]!.fingerprint}-2`);
  });

  it("leaves out results the tool marked as suppressed, and results without a file", () => {
    const log = JSON.parse(sarif({ rule: "a", path: "a" }, { rule: "b", path: "b", suppressed: true }));
    log.runs[0].results.push({ ruleId: "c", message: { text: "no place" } });
    expect(parseSarif(log, "s").findings.map((f) => f.ruleId)).toEqual(["a"]);
  });

  it("refuses what is not SARIF 2.1", () => {
    expect(() => parseSarif([], "s")).toThrow(SarifError);
    expect(() => parseSarif({ hello: 1 }, "s")).toThrow(SarifError);
    expect(() => parseSarif({ version: "1.0.0", runs: [] }, "s")).toThrow(/not supported/);
    expect(parseSarif({ version: "2.1.0", runs: [] }, "s")).toEqual({ tool: "unknown", findings: [] });
  });
});

describe("normalizePath and mask", () => {
  it("gives the path the repository knows", () => {
    expect(normalizePath("file:///src/a.js")).toBe("src/a.js");
    expect(normalizePath("./src/a%20b.js")).toBe("src/a b.js");
  });
  it("hides tokens by their prefix too", () => {
    expect(mask("ghp_abcdefghijklmnopqrstu leaked")).toBe("*** leaked");
  });
});
