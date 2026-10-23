# secrets

[![CI](https://github.com/openasy/secrets/actions/workflows/ci.yml/badge.svg)](https://github.com/openasy/secrets/actions/workflows/ci.yml)
[![Node.js 26 LTS](https://img.shields.io/badge/node-26%20LTS-339933?logo=nodedotjs&logoColor=white)](./.nvmrc)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](./LICENSE)

The [OpenAsy](https://github.com/openasy) Secrets product: **where** secrets leaked in your repositories, and never the
secrets themselves (ADR 0038). Your pipeline runs [gitleaks](https://github.com/gitleaks/gitleaks),
[TruffleHog](https://github.com/trufflesecurity/trufflehog) or another scanner that writes
[SARIF](https://sarifweb.azurewebsites.net/) and sends the result here. A pull request fails for a secret it adds.

```
CI: gitleaks detect --report-format sarif  ──POST /api/v1/scans──▶  secrets  ──▶  { new, blocking, passed }
                                                                      └── where, since when, what was decided; never the secret
```

## The secret is never kept

Reports are read in memory. Snippets and matches are dropped, messages are masked for anything that looks like a key,
token or password, and a finding is stored as its rule, file, line and a **fingerprint**: a hash of the rule, the file
and the match, salted with a random value made on first start and kept in the database. The same secret has the same
fingerprint on every branch of this installation and on no other, and a fingerprint cannot be turned back into the key.
No table has a snippet column, and the tests check that no secret appears in the database or in an API answer.

Treat scanner output as sensitive until it has been sent: masking by pattern can miss a secret in a message.

## How a scan is compared

- A scan of the **default branch** is the baseline. It adopts what is there and never fails a pipeline. What it stops
  reporting is marked fixed, and opens again if it returns.
- Any other scan, or any scan with `pullRequest`, reports only findings the baseline does not have and nobody has
  decided about. A repository fails a check for **any** new finding by default (change **fail on** under the repository).
- A finding keeps its identity when its line moves. A different secret in the same place is a new finding.
- Decisions stay with the fingerprint, on every branch: **revoked** (the key was rotated, with a reason: the real fix),
  **false positive** (with a reason) and **accepted risk** (with a reason and an end date).

## Run

```bash
openssl rand -hex 32 > openasy-kek
export SECRETS_INGEST_TOKEN=$(openssl rand -hex 32)
docker compose up -d
docker compose logs secrets | grep 'no owner yet'
```

Open the link from the log once to create the owner account; there is no default password (ADR 0013). The UI and API
are on http://localhost:8080, the API reference at http://localhost:8080/api/docs/.

```bash
gitleaks detect --report-format sarif --report-path results.sarif
curl -sf -X POST -H "Authorization: Bearer $SECRETS_INGEST_TOKEN" -H 'content-type: application/json' \
  --data-binary @results.sarif \
  "https://secrets.example.com/api/v1/scans?repository=acme/web&branch=$BRANCH&commit=$SHA&pullRequest=$PR" > scan.json
jq -e '.passed' scan.json
```

`repository` and `branch` are required. A new repository uses `main` as its default branch unless you send
`defaultBranch`. The body may be gzipped (`Content-Encoding: gzip`), up to 64 MiB unpacked and 50,000 results.

`openasy-kek` encrypts sign-in secrets in the database (ADR 0021). Keep it apart from the volume and with your backups.

| Variable | Default | |
| --- | --- | --- |
| `PORT` | `8080` | HTTP port |
| `SECRETS_PUBLIC_URL` | `http://localhost:8080` | The address people open, with `https://` behind your TLS proxy |
| `OPENASY_PRODUCTS` | | The install's other OpenAsy products, for the product switcher. Give every product the same value |
| `SECRETS_INGEST_TOKEN` | | Lets CI send scans and nothing else. An API token with the editor role works too |
| `SECRETS_KEY_FILE` | `/run/secrets/openasy-kek` | 32-byte key-encryption key |
| `SECRETS_DB` | `/data/secrets.db` | SQLite file (WAL), on the `/data` volume |
| `SECRETS_RETENTION_DAYS` | `365` | Scans, and fixed findings nobody decided about, older than this are deleted |
| `SECRETS_METRICS_PORT` | | Serve `/metrics` on this port only (ADR 0026) |
| `SECRETS_HEADLESS` | `false` | `true` serves only the API |
| `SECRETS_PASSWORD_SIGN_IN`, `OPENASY_OIDC_*` | | Sign-in, as in every OpenAsy product ([@openasy/auth](https://github.com/openasy/auth)) |

The container runs as non-root with a read-only root filesystem, no capabilities and `no-new-privileges`.

## Roles

Viewers see everything; editors also decide about findings and send scans; admins also change a repository's policy and
delete it, and manage members and API tokens (ADR 0003).

## Develop

```bash
npm install
npm test        # SARIF parsing, the secret never kept, comparison with the baseline, decisions, and every API response against openapi.json
npm run dev     # the UI, with the API on :8080
```

## Licence

AGPL-3.0 (ADR 0008).
