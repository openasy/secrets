import { gzipSync } from "node:zlib";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { sarif, startApp, type TestResult } from "./test-app.ts";

let app: Awaited<ReturnType<typeof startApp>>;
beforeAll(async () => {
  app = await startApp({ version: "0.1.0" });
});
afterAll(() => app.close());

const AWS = "AKIAIOSFODNN7EXAMPLE";
const TOKEN = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";
const aws: TestResult = { rule: "aws-access-key", path: "deploy/up.sh", line: 4, code: `KEY=${AWS}`, message: "Detected an AWS access key" };
const gh: TestResult = { rule: "github-pat", level: "error", path: "ci/release.yml", line: 20, code: `token: ${TOKEN}`, message: "Detected a GitHub token" };
const generic: TestResult = { rule: "generic-api-key", score: 3, path: "app/config.py", line: 2, code: "API = 'k3y-value-0042'", message: "Detected a generic API key" };

const json = async (res: Response) => (await res.json()) as any;
const baseline = (...r: TestResult[]) => app.scan({ repository: "acme/web", branch: "main", commit: "aaaa1111" }, sarif(...r));
const pull = (n: string, ...r: TestResult[]) => app.scan({ repository: "acme/web", branch: `feature-${n}`, pullRequest: n }, sarif(...r));
const repo = async () => (await json(await app.admin("/api/v1/repositories"))).repositories[0];

describe("scans", () => {
  it("adopts the default branch, and fails nothing for what is already there", async () => {
    const scan = await json(await baseline(aws, gh, generic));
    expect(scan).toMatchObject({ kind: "baseline", total: 3, new: 3, blocking: 0, passed: true, failOn: "low" });
  });

  it("fails a pull request for any new secret, and not for moved ones", async () => {
    const scan = await json(await pull("5", { ...aws, line: 40 }, gh, generic, { rule: "slack-token", path: "bot.py", code: "xoxb-1234-abcdefgh", message: "Detected a Slack token" }));
    expect(scan).toMatchObject({ kind: "change", new: 1, blocking: 1, passed: false });
    expect(scan.findings.map((f: { rule: string }) => f.rule)).toEqual(["slack-token"]);
  });

  it("never keeps, logs or returns a secret", async () => {
    await pull("6", { rule: "slack-token", path: "bot.py", code: "xoxb-1234-abcdefgh", message: "Slack token xoxb-1234-abcdefgh" });
    const dump = JSON.stringify([
      ...app.db.prepare("SELECT * FROM findings").all(),
      ...app.db.prepare("SELECT * FROM scan_findings").all(),
      ...app.db.prepare("SELECT * FROM scans").all(),
      ...app.db.prepare("SELECT * FROM repositories").all(),
    ]);
    const api = JSON.stringify([await json(await app.admin("/api/v1/findings")), await json(await app.admin(`/api/v1/repositories/${(await repo()).id}/scans`))]);
    for (const secret of [AWS, TOKEN, "k3y-value-0042", "xoxb-1234-abcdefgh"]) {
      expect(dump, secret).not.toContain(secret);
      expect(api, secret).not.toContain(secret);
    }
    // No table holds a snippet at all.
    for (const table of ["findings", "scan_findings"]) {
      expect((app.db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>).map((c) => c.name)).not.toContain("snippet");
    }
  });

  it("resolves what the default branch stops reporting, and opens it again if it returns", async () => {
    await baseline(aws, generic);
    const r = await repo();
    expect((await json(await app.admin(`/api/v1/repositories/${r.id}/findings?status=resolved`))).findings.map((f: { rule: string }) => f.rule)).toEqual(["github-pat"]);
    expect(await json(await pull("7", aws, generic, gh))).toMatchObject({ new: 1 });
    await baseline(aws, generic, gh);
    expect((await json(await app.admin(`/api/v1/repositories/${r.id}/findings?status=resolved`))).findings).toEqual([]);
  });
});

describe("decisions", () => {
  const inDays = (d: number) => new Date(Date.now() + d * 86_400_000).toISOString();
  const decide = async (rule: string, body: unknown, status = "open") => {
    const r = await repo();
    const f = (await json(await app.admin(`/api/v1/repositories/${r.id}/findings?q=${rule}&status=${status}`))).findings[0];
    return app.admin(`/api/v1/repositories/${r.id}/findings/${f.fingerprint}`, { method: "PUT", body: JSON.stringify(body) });
  };

  it("takes revoked as the real fix, with a reason and no end date", async () => {
    expect((await decide("github-pat", { state: "revoked", reason: "" })).status).toBe(422);
    const done = await json(await decide("github-pat", { state: "revoked", reason: "Token rotated in GitHub on 22 Oct" }));
    expect(done).toMatchObject({ rule: "github-pat", triage: { state: "revoked", by: "admin token", expiresAt: null, active: true } });
    expect((await repo()).open).toEqual({ critical: 0, high: 1, medium: 0, low: 1 });
    // The old key coming back in a pull request is not a second failure.
    expect(await json(await pull("8", aws, generic, gh))).toMatchObject({ new: 0, passed: true });
  });

  it("needs an end for accepted risk, and lets a false positive stand", async () => {
    expect((await decide("generic-api-key", { state: "accepted", reason: "A test value" })).status).toBe(422);
    expect((await decide("generic-api-key", { state: "accepted", reason: "A test value", expiresAt: inDays(400) })).status).toBe(422);
    expect((await decide("generic-api-key", { state: "false-positive", reason: "A placeholder", extra: 1 })).status).toBe(422);
    expect(await json(await decide("generic-api-key", { state: "false-positive", reason: "A placeholder in the sample config" }))).toMatchObject({ triage: { state: "false-positive" } });
    expect(await json(await decide("generic-api-key", { state: "open" }, "suppressed"))).toMatchObject({ triage: null });
  });
});

describe("repositories and access", () => {
  it("fails for any finding by default, and the policy can change", async () => {
    const r = await repo();
    expect(r).toMatchObject({ failOn: "low", defaultBranch: "main" });
    const patch = (body: unknown) => app.admin(`/api/v1/repositories/${r.id}`, { method: "PATCH", body: JSON.stringify(body) });
    expect((await patch({ failOn: "critical" })).status).toBe(200);
    expect(await json(await pull("9", aws, generic, gh, { rule: "x", path: "x.py", code: "pw-1", message: "m" }))).toMatchObject({ new: 1, blocking: 0, passed: true });
    expect((await patch({ failOn: "urgent" })).status).toBe(422);
    expect((await patch({})).status).toBe(422);
    expect((await app.admin(`/api/v1/repositories/${r.id}`, { method: "DELETE" })).status).toBe(204);
    expect((await json(await app.admin("/api/v1/summary"))).repositories).toBe(0);
  });

  it("takes gzip, refuses what it cannot compare, and asks for a token", async () => {
    const send = (query: Record<string, string>, body: string | Buffer, headers: Record<string, string> = {}) => app.ingest(`/api/v1/scans?${new URLSearchParams(query)}`, { method: "POST", body, headers });
    expect((await send({ repository: "acme/api", branch: "main" }, gzipSync(sarif(aws)), { "content-encoding": "gzip" })).status).toBe(201);
    expect((await send({ repository: "acme/api", branch: "main" }, "{nope")).status).toBe(422);
    expect((await send({ branch: "main" }, sarif())).status).toBe(422);
    expect((await fetch(`${app.base}/api/v1/scans?repository=a&branch=main`, { method: "POST", body: sarif() })).status).toBe(401);
    expect((await app.ingest("/api/v1/findings")).status).toBe(401);
    expect(await json(await fetch(`${app.base}/api/v1/version`))).toEqual({ product: "secrets", version: "0.1.0" });
    const metrics = await (await fetch(`${app.base}/metrics`)).text();
    expect(metrics).toContain('openasy_build_info{product="secrets",version="0.1.0"} 1');
  });

  it("keeps one salt for the installation", () => {
    const rows = app.db.prepare("SELECT value FROM settings WHERE key = 'fingerprint_salt'").all() as Array<{ value: string }>;
    expect(rows).toHaveLength(1);
    expect(rows[0]!.value).toMatch(/^[0-9a-f]{64}$/);
  });
});
