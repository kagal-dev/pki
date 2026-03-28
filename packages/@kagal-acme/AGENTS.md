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
| `@kagal/acme/schema` | Phase 2 (done) | Valibot validators conforming to `/types` |
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

## Schema Sub-path Patterns

### File structure

Each [`schema/*.ts`][schema] mirrors a type file
(`types/objects/*.ts`, `types/requests/*.ts`, or
`types/jws/*.ts`). Leaf schemas
([`encoding`][s-encoding], [`identifier`][s-identifier],
[`jwk`][s-jwk], [`renewal-info`][s-renewal-info],
[`directory`][s-directory]) have no schema dependencies.
Compound schemas ([`jws`][s-jws],
[`problem`][s-problem],
[`finalize`][s-finalize],
[`revoke-cert`][s-revoke-cert],
[`challenge`][s-challenge],
[`authorization`][s-authorization],
[`account`][s-account], [`order`][s-order],
[`new-account`][s-new-account],
[`new-order`][s-new-order],
[`new-authz`][s-new-authz],
[`key-change`][s-key-change]) compose from leaves.

### `looseObject` vs `strictObject`

Three categories:

- **Response objects** — `v.looseObject()`, unknown
  fields pass through for forward compatibility.
- **Request payloads** — `v.strictObject()`, the
  client controls the structure. Also used for small
  fixed structures (`FlattenedJWSSchema`).
- **Decoded JWS headers** — `v.looseObject()`, JWS
  headers allow additional registered and private
  parameters (RFC 7515 §4.1).

### Variant discrimination

[`ChallengeSchema`][s-challenge] discriminates on `type`,
[`AuthorizationSchema`][s-authorization] on `status`,
[`JWKSchema`][s-jwk] on `kty` (EC, OKP, RSA).
Shared fields live in a spread object (`challengeBase`,
`authorizationBase`) that each variant branch includes:

```typescript
const challengeBase = {
  url: v.string(),
  status: v.picklist(challengeStatuses),
  ...
};

export const ChallengeSchema = v.variant('type', [
  v.looseObject({
    ...challengeBase,
    type: v.literal('http-01'),
  }),
  ...
]);
```

### Union + check

[`ACMERequestHeaderSchema`][s-jws] enforces `jwk`
XOR `kid` (RFC 8555 §6.2) using `v.union` with two
`looseObject` branches piped through `v.check` for
mutual exclusion. `v.variant` cannot express this —
neither field has literal values suitable as a
discriminant.

### Const tuple reuse

Status fields use `v.picklist()` with the `as const`
tuples from `/types` — single source of truth:

```typescript
import { orderStatuses } from '../types/constants/status';
// ...
status: v.picklist(orderStatuses),
```

Variant discriminants (`type`, `status`) use inline
`v.literal()` — necessary for `v.variant()` branch
discrimination. Catch-all branches derive their
picklist from the shared tuple via `.filter()`
(e.g. `authorizationOtherStatuses`).

### Validation API

[`schema/index.ts`][s-index] exports `validate*()`
functions that return
`ValidationResult<T>` — a discriminated union on
`success`:

```typescript
const result = validateOrder(json);
if (result.success) {
  result.data;   // Order
} else {
  result.issues; // BaseIssue<unknown>[]
}
```

The `data` field returns the hand-written type from
`/types`, not Valibot's `InferOutput`.

### Conformance tests

[`conformance.types.ts`][s-conformance] asserts
bidirectional assignability between each schema's
`InferOutput` and the hand-written type. If schema
and type drift, `tsc` fails.

`DeepStripIndex<T>` recursively removes the
`[key: string]: unknown` index signature that
`looseObject` adds to `InferOutput`, so
bidirectional `toExtend` checks work against
hand-written interfaces. Wrap new schema outputs
with `SchemaOutput<typeof XSchema>` — it applies
the stripping automatically.

### Scope

Schemas cover everything `/utils` needs to
structurally validate after decoding and before
cryptographic verification: response objects, request
payloads, and decoded JWS protected headers.
The pipeline is: `/utils` decodes → `/schema`
validates → `/utils` verifies.

### Adding a new schema

1. Create `schema/{name}.ts` mirroring the type
2. Add bidirectional `expectTypeOf` pair in
   [`conformance.types.ts`][s-conformance]
3. Export schema and `validate*()` from
   [`schema/index.ts`][s-index]
4. Add runtime tests in `schema/__tests__/`

<!-- references -->
[root]: ../../AGENTS.md
[constants]: src/types/constants/
[utils]: src/types/utils.ts
[challenge]: src/types/objects/challenge.ts
[authorization]: src/types/objects/authorization.ts
[problem]: src/types/objects/problem.ts
[jws]: src/types/jws/jws.ts
[schema]: src/schema/
[s-index]: src/schema/index.ts
[s-encoding]: src/schema/encoding.ts
[s-identifier]: src/schema/identifier.ts
[s-problem]: src/schema/problem.ts
[s-jws]: src/schema/jws.ts
[s-jwk]: src/schema/jwk.ts
[s-renewal-info]: src/schema/renewal-info.ts
[s-directory]: src/schema/directory.ts
[s-challenge]: src/schema/challenge.ts
[s-authorization]: src/schema/authorization.ts
[s-account]: src/schema/account.ts
[s-order]: src/schema/order.ts
[s-finalize]: src/schema/finalize.ts
[s-revoke-cert]: src/schema/revoke-cert.ts
[s-new-account]: src/schema/new-account.ts
[s-new-order]: src/schema/new-order.ts
[s-new-authz]: src/schema/new-authz.ts
[s-key-change]: src/schema/key-change.ts
[s-conformance]: src/schema/__tests__/conformance.types.ts
