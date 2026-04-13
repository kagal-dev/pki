# @kagal/pki

Monorepo for PKI packages: an ACME protocol library
and a private certificate authority.

## Packages

### [`@kagal/acme`](packages/@kagal-acme/)

Platform-neutral ACME protocol library (RFC 8555).
Both client and server implemented as resumable state
machines with JSON-serialisable state and injected
dependencies — the machine owns protocol logic, the
consumer owns persistence, key material, and policy.
Works on any platform with WebCrypto.

Sub-path exports:

| Export | Description | Deps |
|--------|-------------|------|
| `@kagal/acme/types` | Interfaces, const tuples, `ReadonlySet` constants | none |
| `@kagal/acme/schema` | Valibot validators | valibot |
| `@kagal/acme/utils` | CSR parsing, cert inspection, ARI cert ID | valibot, WebCrypto |
| `@kagal/acme/client` | Client state machines | /schema, /utils (valibot, WebCrypto) |
| `@kagal/acme/server` | Server state machines | /schema, /utils (valibot, WebCrypto) |

Extensions supported from day one: ARI (RFC 9773)
and Profiles (draft-ietf-acme-profiles).

### [`@kagal/ct`](packages/@kagal-ct/)

Platform-neutral Certificate Transparency library
(RFC 9162).

| Export | Description | Deps |
|--------|-------------|------|
| `@kagal/ct/types` | CT interfaces (STH, SCT, proofs, log entries) | none |
| `@kagal/ct/schema` | Valibot validators | valibot |

### [`@kagal/ca`](packages/@kagal-ca/)

Challenge-less, EAB-driven private CA engine for
Cloudflare Workers. Runs as a single Durable Object
per CA with SQLite storage. Standard ACME clients
(certbot, acme.sh) talk to it over HTTPS.

`@kagal/ca` is a minimal orchestrator — all ACME
protocol logic lives in `@kagal/acme/server`. The CA
handles HTTP parsing, SQLite persistence, deps wiring
(account/EAB key lookup, CA signing, enrollment-based
policy), and DO alarm scheduling.

Beyond the ACME surface:

- **Management plane (RPC)** — EAB provisioning,
  identity enrollment, direct issuance, revocation,
  certificate queries
- **PKI endpoints** — CA chain, CRL, Certificate
  Transparency log (RFC 6962) with SCT embedding
- **`issueDirect`** — programmatic issuance via RPC,
  bypassing the ACME flow but sharing storage

## Build Tooling

### [`@kagal/build-tsdocs`](packages/@kagal-build-tsdocs/)

TSDoc extraction hook for unbuild. Extracts documented
symbols at build time and writes per-export JSON files
plus a unified `api.json` manifest.

| Export | Description | Deps |
|--------|-------------|------|
| `@kagal/build-tsdocs` | `newDocumentsHook()` factory, types | tsdoc-markdown, unbuild (peer) |

## Development

```sh
pnpm install
pnpm precommit   # build → lint → type-check → test
```

## Licence

[MIT](LICENCE.txt)
