# AGENTS.md — @kagal/acme

Guidance for AI coding assistants working within the
`@kagal/acme` package. Read the root [`AGENTS.md`][root]
first for monorepo-wide conventions.

## Package Role

Platform-agnostic ACME protocol library (RFC 8555).
No Cloudflare types, no Node-specific APIs.
The `/types` sub-path has zero runtime dependencies.
The `/schema` sub-path depends only on Valibot.
The `/utils` sub-path uses WebCrypto and
`btoa`/`atob` for base64url codec, random bytes,
and RFC 7638 JWK thumbprint; `jose` for WebCrypto
JWK export and ACME JWS verification;
`/schema` for structural validation in `parseJWK`,
`exportJWK`, and `parseJWS`; and `/error` so
`parseJWS` can throw `ProblemError` with the RFC
8555 §6.7 URN already resolved (`malformed`,
`badSignatureAlgorithm`, `unauthorized`). It will
extend with `@peculiar/x509` + `pkijs` for CSR,
cert, and ARI helpers.
The `/types` sub-path also exposes pure data factories
(`newProblem`, `newSubproblem`) for building RFC 7807
documents with the URN→status table applied — used by
deps callbacks whose contract returns a `Problem` rather
than throwing.
The `/error` sub-path layers throwable Error wrappers
on top: `ProblemError` and `SubproblemError` delegate
to `newProblem` / `newSubproblem` for document
construction, then wrap the result in an `Error` for
fail-fast control flow. `ProblemError.compound`
aggregates `SubproblemError` instances or plain
`Subproblem` documents into a `compound` Problem.
Depends only on `/types`.
The `/client` and `/server` sub-paths compose
`/schema` and `/utils`.

## Sub-path Exports

### Current

| Export | Purpose |
|--------|---------|
| `@kagal/acme/types` | Type definitions, runtime constants, branded strings, RFC 7807 data factories |
| `@kagal/acme/schema` | Valibot validators conforming to `/types` |
| `@kagal/acme/utils` | base64url codec, random bytes, RFC 7638 JWK thumbprint, JWK export / parse, ACME JWS parse + verify, `mustMembers` |
| `@kagal/acme/error` | `ProblemError` / `SubproblemError` throwable Error wrappers around `/types`'s `newProblem` / `newSubproblem`, with URN-aware shortcuts (`malformed` / `unauthorized` / `serverInternal` / `compound`; `rejectedIdentifier` / `caa`) |
| `@kagal/acme/client` | Stub — no surface yet |
| `@kagal/acme/server` | Stub — no surface yet |

### Planned

| Export | Purpose |
|--------|---------|
| `@kagal/acme/utils` | + CSR, cert, ARI, PEM utilities |
| `@kagal/acme/client` | + Client state machines |
| `@kagal/acme/server` | + Server state machines |

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
without discrimination ([`ACMEProtectedHeader`][jws]):

```typescript
interface ACMEProtectedHeader extends JWSProtectedHeader {
  nonce: string
  url: string
}
```

Sibling shapes that share fields but neither is a
superset use a file-private `*Base` and both
`extend` it. [`Problem`][problem] and
[`Subproblem`][problem] follow this pattern: RFC
8555 §6.7.1 forbids `identifier` at the top level,
so `Problem extends Subproblem` would
structurally accept what the spec forbids.
Both extend `ProblemBase` instead — `Subproblem`
adds `identifier?`, `Problem` adds `subproblems?`.

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

Status-mapping tables (e.g. [`errorStatus`][error-type])
are a sibling pattern: typed as
`Readonly<Record<X, T>>` for compile-time exhaustiveness
on `X`. They live in the same file as the
tuple/type/set triple they index.

Pure data factories (e.g. [`newProblem`][problem],
[`newSubproblem`][problem]) live alongside their types
in `types/objects/` and return plain objects suitable
for the wire form. Status defaults derive from the
matching status table; overrides go through an
`options` parameter.

### Branded strings

[`Base64url`][encoding], [`Base64urlAlphabet`][encoding],
and [`PEM`][encoding] are branded `string` types —
intersections such as
`string & { readonly _Base64urlBrand: void }`,
keyed by string-named phantom properties. String
keys (not a `unique symbol` — see the
[rationale comment in `types/encoding.ts`][encoding])
so the brand is nameable across module boundaries
without TS4023 on declaration emit. `Base64urlAlphabet`
is the alphabet-only sibling of `Base64url`: it
constrains characters to the RFC 4648 §5 alphabet
without requiring byte-framed length, which is what
RFC 8555 §8.1 calls for on `Challenge.token` ("only
characters in the base64url alphabet", no
decode-framing guarantee).
Producers in `/utils` (`encodeBase64url`,
`getRandom`, `jwkThumbprint`) return the brand
directly; the matching schemas
([`Base64urlSchema`][s-encoding],
[`Base64urlAlphabetSchema`][s-encoding],
[`PEMSchema`][s-encoding]) transform to the brand
on the last pipe step. Plain `string` cannot be
assigned to a branded slot — consumers must go
through an accessor (`asBase64url`,
`asBase64urlAlphabet`, `asPEM`), a producer, or a
schema.

The accessors are unvalidated — use them only at
trust boundaries (known-correct encoder output,
row loaded from a store validated at ingest).
Untrusted input must go through the schema.

The brand is nominal at the type level only; at
runtime the value is a plain `string`, so
`JSON.stringify`, concatenation, and storage
writes work transparently.

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

### Branded outputs

Encoding schemas end in `v.transform` so their
`InferOutput` matches the hand-written brand, not
bare `string`. Callers receive
[`Base64url`][encoding] / [`PEM`][encoding] from
`validateBase64url` / `validatePEM` without a
cast.

The conformance helper `DeepStripIndex<T>`
short-circuits on `T extends string` so the
mapped rewrite (whose job is stripping
`looseObject`'s index signature) doesn't also
strip the primitive side of a branded
intersection — otherwise `Base64url` would
collapse to `{}` in the stripped form.

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

## Utils Sub-path Patterns

### Producers return branded types

Every `/utils` function that outputs encoded bytes
returns [`Base64url`][encoding] directly, not
`string`. The brand travels from the producer into
every consumer that types its inputs against
`Base64url` — no intermediate `as` casts, no
accidental mixing with plain strings. The brand
conformance file
`src/types/__tests__/encoding.types.ts` asserts
`ReturnType<typeof encodeBase64url>` is exactly
`Base64url`; if a producer ever widens back to
`string`, the type-check fails.

<!-- cspell:words destructures -->
### canonicalJWK literal `kty`

[`canonicalJWK`][u-jwk] switches on `jwk.kty` and
emits the thumbprint input with `kty: 'EC'` /
`'OKP'` / `'RSA'` as string literals, not
`kty: jwk.kty`. TypeScript's discriminated-union
narrowing would let either form compile — the
literal form is preferred because:

- The canonical form is self-documenting at the
  return site: each branch lists exactly the
  required RFC 7638 members.
- There is no DRY payoff; the set of `kty` values
  is RFC-fixed.
- Defence-in-depth if a future refactor
  destructures or reshapes `jwk` before the
  switch.

### `String.fromCodePoint` argument limit

[`encodeBase64url`][u-encoding] spreads the byte
array as call arguments to
`String.fromCodePoint(...bytes)`. V8's
argument-limit (~100K) caps the safe input size.
Fine for signatures, hashes, CSRs; revisit with a
chunked implementation if full certificate chains
ever pass through this helper.

### Forgiving `atob`

[`decodeBase64url`][u-encoding] substitutes
URL-safe characters (`-` → `+`, `_` → `/`) and
passes the result straight to `atob` without
re-padding. The HTML spec's forgiving-base64
decoder accepts missing `=` padding, and every
browser / worker runtime conforms. Don't add a
re-pad step — it would be dead code.

## Errors Sub-path Patterns

### Data factories vs Error wrappers

Two layers ship side by side:

- **`/types` data factories** ([`newProblem`,
  `newSubproblem`][problem]) build plain RFC 7807
  documents — pure data, no `Error` instance, no
  `cause`, no stack trace. Use these when the call
  site's contract is to **return** a `Problem` rather
  than throw — for example `@kagal/acme/server`'s
  planned `checkPolicy: () => Problem | undefined`,
  or any `/types`-only consumer that doesn't want to
  pull in the Error wrappers.
- **`/error` throwable wrappers**
  ([`ProblemError`, `SubproblemError`][problem-error])
  delegate to the data factories for document
  construction and wrap the result in an `Error`
  subclass for fail-fast control flow. Use these
  inside protocol logic where you want a `throw` to
  short-circuit a validation chain and an outer
  `catch (err instanceof ProblemError)` boundary to
  surface the document on the wire.

The wrappers preserve full referential equality with
the data factories — `ProblemError.malformed(d).problem`
is identical in shape to `newProblem('…malformed', d)`
— so callers can switch layers without changing the
wire output.

### Factories vs constructor

Reach for a named factory ([`malformed`, `unauthorized`,
`serverInternal`, `compound`][problem-error]) to derive
the conventional HTTP status from
[`errorStatus`][error-type]. Use the generic
`of(type, detail?, options?)` for URNs without a named
factory (`badNonce`, `caa`, `rateLimited`, …). Reach
for the constructor only when shaping a Problem the
factories don't cover — custom `title`, RFC 7807
extension fields, or a pre-built document round-tripped
from the wire.

### Status overrides

`options.status` overrides the conventional value from
[`errorStatus`][error-type] while keeping the URN
classification. Boulder reuses `malformed` with
non-default statuses (404 no-such-resource, 405
method-not-allowed):

```typescript
ProblemError.malformed('No such order', { status: 404 });
```

Omit `status` to fall back to the table.

### Per-identifier failures

[`SubproblemError`][problem-error] is the per-identifier
sibling of `ProblemError`: it wraps a [`Subproblem`][problem]
(RFC 8555 §6.7.1) instead of a Problem and carries the
optional `identifier` field that the top-level Problem is
forbidden from carrying. Each per-identifier validator
throws a `SubproblemError`; the caller aggregates the
results — typically via `Promise.allSettled` — and rolls
them into a `compound` Problem:

```typescript
const failures: SubproblemError[] = [];
for (const id of identifiers) {
  if (!await checkCAA(id)) {
    failures.push(SubproblemError.caa(id, 'CAA forbids issuance'));
  }
}
if (failures.length > 0) {
  throw ProblemError.compound(failures, 'Pre-issuance checks failed');
}
```

Use the named shortcuts (`rejectedIdentifier`, `caa`) for
the URNs an ACME server emits per identifier most often;
fall back to `SubproblemError.of(type, identifier?, detail?, options?)`
for the rest. `ProblemError.compound` accepts any mix of
plain `Subproblem` documents and `SubproblemError`
instances, unwrapping the latter before serialisation —
`Error.cause` on individual `SubproblemError` instances
is dropped, since `cause` lives on the `Error` wrapper
(not on the `Subproblem` document) and is not part of the
wire form.

**Wire-boundary contract.** A `SubproblemError` whose
`subproblem` was serialised directly as
`application/problem+json` would put `identifier` at the
top level of the document — RFC 8555 §6.7.1 forbids
exactly that. The HTTP boundary catches `ProblemError`
only; `SubproblemError` always funnels through
`ProblemError.compound` first.

### Wire form

`error.problem` is the document that lands in the
`application/problem+json` body — serialise the carried
document directly (`JSON.stringify(err.problem)`), not
the `Error` itself. `compound()` deep-copies the caller's
`subproblems` via `structuredClone`, so post-throw
mutation of either the source array or any contained
Subproblem does not leak into the wire form. The
constructor takes a Problem document by reference —
advanced callers using `new ProblemError(doc)` own the
hermeticity of the document they pass.

<!-- references -->
[root]: ../../AGENTS.md
[constants]: src/types/constants/
[error-type]: src/types/constants/error-type.ts
[utils]: src/types/utils.ts
[encoding]: src/types/encoding.ts
[challenge]: src/types/objects/challenge.ts
[authorization]: src/types/objects/authorization.ts
[problem]: src/types/objects/problem.ts
[problem-error]: src/error/problem.ts
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
[u-encoding]: src/utils/encoding.ts
[u-jwk]: src/utils/jwk.ts
