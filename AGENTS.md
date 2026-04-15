# AGENTS.md

This file provides guidance to AI coding assistants
(Claude Code, GitHub Copilot, Cody, etc.) when working
with code in the kagal-dev/pki monorepo.

## Project Overview

This monorepo contains four MIT-licensed TypeScript
packages for PKI (Public Key Infrastructure):

- **`@kagal/acme`** — platform-neutral ACME protocol
  library (RFC 8555)
- **`@kagal/ct`** — platform-neutral Certificate
  Transparency types and schema validators (RFC 9162)
- **`@kagal/ca`** — challenge-less, EAB-driven private
  CA engine for Cloudflare Workers
- **`@kagal/build-tsdocs`** — TSDoc extraction hook for
  unbuild, used across the other packages

The packages follow a strict layering:

```text
consumer Worker (embeds @kagal/ca)
      │ depends on
      ▼
@kagal/ca (Cloudflare-specific orchestrator)
      │ depends on
      ▼
@kagal/acme (platform-agnostic protocol library)
```

Each layer depends downward only. `@kagal/acme` knows
nothing about `@kagal/ca`. `@kagal/ca` knows nothing
about the consumer application.

## Monorepo Structure

```text
pki/
├── packages/
│   ├── @kagal-acme/           # @kagal/acme
│   │   └── src/
│   │       ├── index.ts       # Root entry (VERSION)
│   │       ├── types/         # Sub-path: @kagal/acme/types
│   │       ├── schema/        # Sub-path: @kagal/acme/schema
│   │       ├── utils/         # Sub-path: @kagal/acme/utils
│   │       ├── client/        # Sub-path: @kagal/acme/client
│   │       └── server/        # Sub-path: @kagal/acme/server
│   ├── @kagal-build-tsdocs/   # @kagal/build-tsdocs
│   │   └── src/
│   │       ├── index.ts       # newDocumentsHook(), VERSION
│   │       ├── types.ts       # Manifest types, DocEntry re-export
│   │       ├── extract.ts     # Symbol extraction logic
│   │       └── write.ts       # JSON output and logging
│   ├── @kagal-ca/             # @kagal/ca
│   │   └── src/
│   │       ├── index.ts       # Root entry (VERSION, CAEnv)
│   │       └── types.ts       # Cloudflare environment bindings
│   └── @kagal-ct/             # @kagal/ct
│       └── src/
│           ├── index.ts       # Root entry (VERSION)
│           ├── types/         # Sub-path: @kagal/ct/types
│           └── schema/        # Sub-path: @kagal/ct/schema
├── docs/                      # Design documents (not published)
├── .github/workflows/         # CI/CD
├── pnpm-workspace.yaml
└── package.json               # Root (private)
```

### `@kagal/acme` Sub-path Exports

| Export | Purpose | Runtime deps |
|--------|---------|--------------|
| `@kagal/acme/types` | Types, const tuples, ReadonlySet, `narrow()` | none |
| `@kagal/acme/schema` | Valibot validators | valibot |
| `@kagal/acme/utils` | Base64url codec, random bytes, JWK thumbprints, `mustMembers` | WebCrypto |

Planned:

| Export | Purpose | Runtime deps |
|--------|---------|--------------|
| `@kagal/acme/utils` | CSR parsing, cert inspection, ARI cert ID, PEM helpers | + valibot, @peculiar/x509, pkijs |
| `@kagal/acme/client` | Client state machines | /schema, /utils |
| `@kagal/acme/server` | Server state machines | /schema, /utils |

The root export (`@kagal/acme`) re-exports types +
client + server. It does NOT re-export schema or utils.

See `packages/@kagal-acme/AGENTS.md` for type-level
patterns and conventions.

### `@kagal/ca` Architecture

`@kagal/ca` is a minimal orchestrator — all ACME
protocol logic lives in `@kagal/acme/server`. The CA
provides:

- **ACME surface** — HTTP layer, deps wiring, state
  persistence, alarm scheduling
- **Management plane (RPC)** — EAB provisioning,
  identity enrolment, direct issuance, revocation
- **PKI endpoints** — CA chain, CRL, Certificate
  Transparency log (RFC 6962) with SCT embedding

It runs as a single Durable Object per CA with SQLite
storage.

## Reference RFCs

Local copies live in `docs/rfc/`:

| File | Subject |
|------|---------|
| `rfc8555.txt` | ACME protocol |
| `rfc5280.txt` | Internet X.509 PKI — Certificate and CRL Profile |
| `rfc6962.txt` | Certificate Transparency v1 |
| `rfc9162.txt` | Certificate Transparency v2 (supersedes 6962) |
| `rfc7515.txt` | JSON Web Signature (JWS) |
| `rfc7517.txt` | JSON Web Key (JWK) |
| `rfc7518.txt` | JSON Web Algorithms (JWA) |
| `rfc7807.txt` | Problem Details for HTTP APIs |
| `rfc8037.txt` | CFRG Curves in JOSE (Ed25519, Ed448) |
| `rfc8737.txt` | ACME TLS-ALPN-01 Challenge |
| `rfc8738.txt` | ACME IP Identifier Validation |
| `rfc9773.txt` | ACME Renewal Information (ARI) |
| `draft-ietf-acme-profiles-01.txt` | ACME Profiles extension |

Read these for authoritative protocol details.

## Common Commands

```bash
pnpm install
pnpm build              # Build all packages
pnpm test               # Test all packages
pnpm lint               # Lint all (root + packages)
pnpm type-check         # Type-check all packages
pnpm precommit          # build → lint → type-check → test
pnpm prepack            # lint:check → per-package prepack
pnpm test:coverage      # test with istanbul coverage report
```

Per-package commands via `--filter`:

```bash
pnpm --filter @kagal/acme build
pnpm --filter @kagal/ca test
```

## Code Style Guidelines

Enforced by .editorconfig and @poupe/eslint-config:

- **Indentation**: 2 spaces
- **Line Endings**: Unix (LF)
- **Charset**: UTF-8
- **Quotes**: Single quotes
- **Semicolons**: Always
- **Module System**: ES modules (`type: "module"`)
- **Line Length**: Max 78 characters preferred
- **Comments**: TSDoc format
- **Naming**: camelCase for variables/functions,
  PascalCase for types/interfaces
- **Spelling**: British English (serialisable,
  behaviour, colour)
- **Final Newline**: Always insert
- **Trailing Whitespace**: Always trim

### Factory functions

Prefer `new` or `make` prefix, not `create`
(e.g. `newFoo()`, `makeFoo()`).

## Development Practices

### Pre-commit (MANDATORY)

Before committing any changes, ALWAYS run:

1. `pnpm precommit`
2. Fix any issues found

### DO

- Use workspace protocol (`workspace:^`) for internal
  dependencies
- Write tests for all new functionality
- Check existing code patterns before creating new ones
- Follow strict TypeScript practices
- Read design docs before making architectural changes
- Build before lint (stubs need building first)

### DON'T

- Create files unless necessary — prefer editing
  existing ones
- Add external dependencies without careful
  consideration
- Ignore TypeScript errors or ESLint warnings
- Import Cloudflare types in `@kagal/acme` — it must
  remain platform-agnostic
- Import value constants from `@kagal/ca` in Node.js
  contexts (build/test configs) — `cloudflare:*`
  modules are workerd-only
- Use relative imports between packages (use workspace
  deps)
- **NEVER use `git add .` or `git add -A`**
- **NEVER commit without explicitly listing files**
- **NEVER use `cd`** — use `pnpm --filter`, `git -C`,
  or relative paths

## Git Workflow

### Commits

- Always use `-s` flag for sign-off
- Write clear messages describing actual changes
- No AI advertising in commit messages
- Focus on the final result, not the iterations

### Direct Commits (MANDATORY)

ALWAYS list files explicitly in the commit command.
Use `git add` only for new/untracked files, then pass
all files (new and modified) to `git commit`.

```bash
git add src/new-file.ts
git commit -sF .tmp/commit-<slug>.txt -- src/new-file.ts src/changed.ts
```

Temporary files use `.tmp/` with a shared prefix:

- Commit messages: `.tmp/commit-<slug>.txt`
- PR descriptions: `.tmp/pr-<slug>.md`

### Commit Message Guidelines

- First line: type(scope): brief description (50 chars)
- Blank line
- Body: what and why, not how (wrap at 72 chars)
- Use bullet points for multiple changes
- Reference issues/PRs when relevant

## TypeScript Configuration

Each package has multiple tsconfig files:

- `tsconfig.json` — source code (no Node types)
- `tsconfig.tools.json` — adds Node types for
  build.config.ts, vitest.config.ts
- `tsconfig.tests.json` — test files and compile-time
  type assertions (`@kagal/ca` also adds
  `@cloudflare/vitest-pool-workers/types`)

The root `tsconfig.json` provides shared compiler
options (ESNext, bundler resolution, strict mode).

## Testing

- All packages use Vitest
- `@kagal/acme` runs tests in Node.js
- `@kagal/ca` uses `@cloudflare/vitest-pool-workers`
  to run tests inside workerd. It has a `wrangler.jsonc`
  for test bindings and a `tsconfig.tests.json` for
  test type-checking.
- Test files: `*.test.ts` under `src/__tests__/`
- `@kagal/cross-test` (external dep) provides the
  conditional stub helper for `prepare` scripts

## Build

- **unbuild** for all packages (ESM + DTS, sourcemaps)
- `build.config.ts` defines entry points — `@kagal/acme`
  has six entries (root + five sub-paths)
- `@kagal/build-tsdocs` provides `newDocumentsHook()` —
  an unbuild `build:done` hook that extracts TSDoc
  symbols and writes per-export JSON to `_docs/` at the
  package root (not inside `dist/`, does not ship to npm)
- `prepare` script: `cross-test -s dist/index.mjs ||
  unbuild --stub` (conditional stubbing)
- `dev:prepare`: `unbuild --stub` (unconditional)

## Publishing

npm packages are published via GitHub Actions using
npm's OIDC trusted publishing with `--provenance`.
No tokens stored as secrets.

1. Push a version tag (`v*`) to trigger `publish.yml`
2. GitHub Actions authenticates to npm via OIDC
3. `pnpm -r publish:maybe` checks each package —
   publishes only if `$name@$version` is not yet on npm
4. `pkg-pr-new` provides preview publishes on non-tag
   pushes

### Setup (per package on npmjs.com)

Each `@kagal/*` package must be configured as a
trusted publisher on npmjs.com:

- **Repository**: `kagal-dev/pki`
- **Workflow**: `publish.yml`
- **Environment**: (none)

## Sibling Repositories

This repo has three siblings under the same org:

- **kagal** — fleet management framework (Cloudflare
  edge). The CA code originated here.
- **json-template** — JSON template engine, intended
  as the base for certificate ACME profiles.
- **cross-test** — shared test utilities.

Conventions (commit style, tooling, CI patterns) should
stay consistent across all four repos.
