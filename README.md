# @kagal/pki

Monorepo for PKI packages: an ACME protocol library
and a private certificate authority.

## Packages

### [`@kagal/acme`](packages/@kagal-acme/)

Platform-neutral ACME protocol library (RFC 8555).
Protocol types, Valibot schemas, and WebCrypto-based
utilities. Works on any platform with WebCrypto.

Extensions supported from day one: ARI (RFC 9773)
and Profiles (draft-ietf-acme-profiles).

See the [package README](packages/@kagal-acme/README.md)
for sub-path exports and usage.

### [`@kagal/ct`](packages/@kagal-ct/)

Platform-neutral Certificate Transparency library
(RFC 9162). See the
[package directory](packages/@kagal-ct/) for sub-path
exports.

### [`@kagal/ca`](packages/@kagal-ca/)

Challenge-less, EAB-driven private CA engine for
Cloudflare Workers. Runs as a single Durable Object
per CA with SQLite storage. Standard ACME clients
(certbot, acme.sh) talk to it over HTTPS.

`@kagal/ca` is a minimal orchestrator — all ACME
protocol logic lives in `@kagal/acme/server`. The CA
handles HTTP parsing, SQLite persistence, deps wiring
(account/EAB key lookup, CA signing, enrolment-based
policy), and DO alarm scheduling.

Beyond the ACME surface:

- **Management plane (RPC)** — EAB provisioning,
  identity enrolment, direct issuance, revocation,
  certificate queries
- **PKI endpoints** — CA chain, CRL, Certificate
  Transparency log (RFC 6962) with SCT embedding
- **`issueDirect`** — programmatic issuance via RPC,
  bypassing the ACME flow but sharing storage

## Development

```sh
pnpm install
pnpm precommit   # dev:prepare → lint → type-check → build → test
```

## Licence

[MIT](LICENCE.txt)
