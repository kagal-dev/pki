# AGENTS.md — @kagal/acme

Guidance for AI coding assistants working within the
`@kagal/acme` package. Read the root [`AGENTS.md`][root]
first for monorepo-wide conventions.

## Package Role

Platform-agnostic ACME protocol library (RFC 8555).
No Cloudflare types, no Node-specific APIs.
The `/types` sub-path has zero runtime dependencies.
The `/schema` sub-path depends only on Valibot.
The `/utils` sub-path will extend `/schema` with
WebCrypto-based validation (Valibot + WebCrypto).
The `/client` and `/server` sub-paths will depend
on `/utils`.

## Sub-path Exports

| Export | Status | Purpose |
|--------|--------|---------|
| `@kagal/acme/types` | Phase 1 (done) | Interfaces, const tuples, ReadonlySet, `narrow()` |
| `@kagal/acme/schema` | Phase 2 | Valibot validators conforming to `/types` |
| `@kagal/acme/utils` | Phase 3+ | CSR, cert, ARI, PEM utilities |
| `@kagal/acme/client` | Phase 3+ | Client state machines |
| `@kagal/acme/server` | Phase 3+ | Server state machines |

## Types Sub-path Patterns

### interface vs type

- **`interface`** — extensible protocol objects, base
  shapes, dependency contracts.
  Examples: `Account`, `Order`, `ChallengeBase`,
  `AuthorizationBase`, `JWSProtectedHeader`.
- **`type`** — sealed data: discriminated unions,
  request payloads, JWK variants, type aliases.
  All request payloads (`requests/`) use `type`.
  Examples: `Authorization`, `Challenge`,
  `NewOrder`, `ECJWK`, `ACMERequestHeader`.
- **type alias** — semantic renaming without
  structural change
  (e.g. `ExternalAccountBinding = FlattenedJWS`).

### Base + intersection

Shared fields live in a `*Base` interface
([`ChallengeBase`][challenge],
[`AuthorizationBase`][authorization]).
Variants use intersection types for discrimination:

```typescript
interface ChallengeBase { url, status, ... }

type HTTPChallenge = ChallengeBase & {
  type: 'http-01'
  token: string
}
```

[`Authorization`][authorization] follows the same pattern
with `AuthorizationBase`. The catch-all variant uses
`Exclude<AuthorizationStatus, 'pending' | 'valid'>`
to stay linked to the constant tuple.

### interface extends

Use when one interface is a strict superset of another
without discrimination ([`Problem`][problem],
[`ACMEProtectedHeader`][jws]):

```typescript
interface Problem extends Subproblem {
  subproblems?: Subproblem[]
}

interface ACMEProtectedHeader extends JWSProtectedHeader {
  nonce: string
  url: string
}
```

### Constants (tuple → type → set)

Every protocol string set follows one pattern:

```typescript
export const orderStatuses = [...] as const;
export type OrderStatus = (typeof orderStatuses)[number];
export const OrderStatuses: ReadonlySet<OrderStatus> = new Set(orderStatuses);
```

All constant files live in [`types/constants/`][constants].
Utility functions (e.g. `narrow()`) live in
[`types/utils.ts`][utils].

### JWS type hierarchy ([`jws.ts`][jws])

```text
JWSProtectedHeader          — RFC 7515: alg, jwk?, kid?
  └─ ACMEProtectedHeader    — RFC 8555: + nonce, url
       └─ ACMERequestHeader — jwk XOR kid (never pattern)
```

- `JWSProtectedHeader` — inner JWS (EAB, key change)
- `ACMEProtectedHeader` — parsing/receiving outer headers
- `ACMERequestHeader` — outer headers with jwk XOR kid enforced

### Naming

- Acronyms stay all-caps: `JWK`, `ECJWK`, `RSAJWK`,
  `HTTPChallenge`, `DNSChallenge`, `TLSALPNChallenge`,
  `ACMEProtectedHeader`. Never `Jwk`, `Http`, `Dns`.

### TSDoc

- `@see` with full RFC URL on every exported
  type/interface.
- `{@link TypeName}` for cross-references.
- `@remarks` for non-obvious constraints.
- `@beta` on draft-spec fields
  (e.g. `profile`, `profiles`).
- `@example` on utility functions.
- Inline `/** comment */` on every property.

### Style

- `};` on closing braces (statement terminator).
- `import type` for all type imports.
- File header comment on every file
  (`// ACME ... (RFC ...)`).
- Alphabetical ordering of exports, union members,
  and imports (enforced by ESLint).
- New exports must be added to `types/index.ts`.
- No circular imports within `types/`.

<!-- references -->
[root]: ../../AGENTS.md
[constants]: src/types/constants/
[utils]: src/types/utils.ts
[challenge]: src/types/objects/challenge.ts
[authorization]: src/types/objects/authorization.ts
[problem]: src/types/objects/problem.ts
[jws]: src/types/jws/jws.ts
