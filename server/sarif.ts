import { createHash } from "node:crypto";

export type Severity = "critical" | "high" | "medium" | "low";
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

export interface Finding {
  /** Stable across moved lines and branches of one installation: a salted hash of the rule, the file and the match. */
  fingerprint: string;
  ruleId: string;
  severity: Severity;
  path: string;
  line: number | null;
  message: string;
}

export class SarifError extends Error {}

/** Most results one upload may hold. */
export const MAX_RESULTS = 50_000;

type Obj = Record<string, any>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const text = (v: unknown, max: number) => (typeof v === "string" && v.trim() ? v.trim().slice(0, max) : null);

/** security-severity is a CVSS-like score that GitHub's convention and most analysers use. */
function fromScore(score: unknown): Severity | null {
  const n = typeof score === "string" ? Number(score) : score;
  if (typeof n !== "number" || !Number.isFinite(n) || n <= 0) return null;
  return n >= 9 ? "critical" : n >= 7 ? "high" : n >= 4 ? "medium" : "low";
}

// A leaked secret is serious until someone shows otherwise: scanners that only say "warning" mean high.
function fromLevel(level: unknown): Severity {
  return level === "error" ? "critical" : level === "note" ? "medium" : "high";
}

/** A path as the repository knows it: no file:// prefix, no ./ and no escaping. */
export function normalizePath(uri: string): string {
  let path = uri;
  try {
    path = decodeURIComponent(uri);
  } catch {
    // keep it as sent
  }
  return path.replace(/^file:\/\/\/?/, "").replace(/^(\.\/)+/, "").replace(/\\/g, "/").slice(0, 1024);
}

const squash = (s: string) => s.replace(/\s+/g, " ").trim();

/** Values that look like keys, tokens or passwords in a message are replaced before it is kept (ADR 0038). */
export function mask(value: string): string {
  return value
    .replace(/((?:password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key|private[_-]?key)["']?\s*[=:]\s*["']?)[^\s&"',;]+/gi, "$1***")
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/g, "Bearer ***")
    .replace(/\b(?:AKIA|ASIA|ghp_|gho_|ghs_|glpat-|xox[abp]-|sk_live_|sk-)[A-Za-z0-9_-]{8,}/g, "***");
}

/** Reads the results of a SARIF 2.1.0 log. Results the tool itself marks as suppressed are left out. */
export function parseSarif(body: unknown, salt: string): { tool: string; findings: Finding[] } {
  if (!isObj(body) || !Array.isArray(body.runs)) throw new SarifError("Send a SARIF 2.1.0 log: a JSON object with a runs array, for example from `gitleaks detect --report-format sarif`.");
  if (typeof body.version === "string" && !body.version.startsWith("2.1")) throw new SarifError(`SARIF ${body.version} is not supported; send version 2.1.0.`);
  const tools: string[] = [];
  const found: Array<Omit<Finding, "fingerprint"> & { match: string | null }> = [];
  for (const run of body.runs) {
    if (!isObj(run)) continue;
    const driver = isObj(run.tool) && isObj(run.tool.driver) ? run.tool.driver : {};
    const name = text(driver.name, 64);
    if (name && !tools.includes(name)) tools.push(name);
    const rules = new Map<string, Obj>();
    if (Array.isArray(driver.rules)) for (const r of driver.rules) if (isObj(r) && typeof r.id === "string") rules.set(r.id, r);
    for (const result of Array.isArray(run.results) ? run.results : []) {
      if (!isObj(result) || (Array.isArray(result.suppressions) && result.suppressions.length > 0)) continue;
      if (found.length >= MAX_RESULTS) throw new SarifError(`A scan may hold at most ${MAX_RESULTS} results.`);
      const ruleId = text(result.ruleId ?? (isObj(result.rule) ? result.rule.id : undefined), 256) ?? "unknown";
      const rule = rules.get(ruleId);
      const location = Array.isArray(result.locations) && isObj(result.locations[0]) && isObj(result.locations[0].physicalLocation) ? result.locations[0].physicalLocation : {};
      const uri = text(isObj(location.artifactLocation) ? location.artifactLocation.uri : undefined, 2048);
      if (!uri) continue; // a result without a file cannot be followed from one scan to the next
      const region = isObj(location.region) ? location.region : {};
      // Only ever hashed: the match is the secret.
      const match = text(isObj(region.snippet) ? region.snippet.text : isObj(location.contextRegion) && isObj(location.contextRegion.snippet) ? location.contextRegion.snippet.text : undefined, 2000);
      const severity =
        fromScore(isObj(result.properties) ? result.properties["security-severity"] : undefined) ??
        fromScore(isObj(rule?.properties) ? rule!.properties["security-severity"] : undefined) ??
        fromLevel(result.level ?? (isObj(rule?.defaultConfiguration) ? rule!.defaultConfiguration.level : undefined));
      found.push({
        ruleId,
        severity,
        path: normalizePath(uri),
        line: Number.isInteger(region.startLine) && region.startLine > 0 ? region.startLine : null,
        message: mask(text(isObj(result.message) ? (result.message.text ?? result.message.markdown) : undefined, 300) ?? text(isObj(rule?.shortDescription) ? rule!.shortDescription.text : undefined, 300) ?? ruleId),
        match,
      });
    }
  }
  // Two matches of one rule on the same code in one file get -2, -3 in the order they were reported, so a pull request
  // that adds a second copy is new.
  const seen = new Map<string, number>();
  const findings = found.map((f): Finding => {
    const base = createHash("sha256").update(`${salt}\n${f.ruleId}\n${f.path}\n${squash(f.match ?? f.message)}`).digest("hex").slice(0, 32);
    const n = (seen.get(base) ?? 0) + 1;
    seen.set(base, n);
    const { match: _match, ...rest } = f;
    return { ...rest, fingerprint: n === 1 ? base : `${base}-${n}` };
  });
  return { tool: tools.join(", ") || "unknown", findings };
}
