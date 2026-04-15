# @kagal/pki

Monorepo for PKI packages: an ACME protocol library
and a private certificate authority.

## Packages

### [`@kagal/acme`](packages/@kagal-acme/)

Platform-neutral ACME protocol library (RFC 8555).
Exports ACME protocol types, Valibot schemas, and
WebCrypto-based utilities (JWK thumbprints, JWK
export / parse, base64url codec, random bytes).
Works on any platform with WebCrypto.

Sub-path exports:

| Export | Description | Deps |
|--------|-------------|------|
| `@kagal/acme/types` | Interfaces, const tuples, `ReadonlySet` constants | none |
| `@kagal/acme/schema` | Valibot validators | valibot |
| `@kagal/acme/utils` | Base64url codec, random bytes, JWK thumbprints, JWK parse | WebCrypto, /schema |
| `@kagal/acme/client` | Stub — no surface yet | none |
| `@kagal/acme/server` | Stub — no surface yet | none |

Planned:

| Export | Description | Deps |
|--------|-------------|------|
| `@kagal/acme/utils` | + CSR parsing, cert inspection, ARI cert ID, PEM helpers | + @peculiar/x509, pkijs |
| `@kagal/acme/client` | + Client state machines | /schema, /utils |
| `@kagal/acme/server` | + Server state machines | /schema, /utils |

Client and server will ship as resumable state
machines with JSON-serialisable state and injected
dependencies — the machine will own protocol logic,
the consumer will own persistence, key material, and
policy.

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
pnpm precommit   # dev:prepare → lint → type-check → build → test
```

## Licence

[MIT](LICENCE.txt)
