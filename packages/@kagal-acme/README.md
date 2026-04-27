# @kagal/acme

Platform-neutral ACME protocol library (RFC 8555).
Protocol types, Valibot schemas, and WebCrypto-based
utilities.

## Sub-path Exports

### Current

| Export | Description | Dependencies |
|--------|-------------|--------------|
| `@kagal/acme/types` | Type definitions, runtime constants, branded strings, RFC 7807 data factories — see [`/types` exports][types-exports] | none |
| `@kagal/acme/schema` | Valibot validators | valibot |
| `@kagal/acme/utils` | base64url codec, random bytes, JWK thumbprint, JWK export / parse | WebCrypto, jose, /schema |
| `@kagal/acme/client` | Stub — no surface yet | none |
| `@kagal/acme/server` | Stub — no surface yet | none |

#### `/types` exports

- Interfaces and const tuples (e.g. `Account`, `Order`, `Identifier`)
- `ReadonlySet` constants for runtime narrowing (e.g. `AccountStatuses`, `OrderStatuses`)
- Branded `Base64url` / `Base64urlAlphabet` / `PEM`
- `errorStatus` — URN→HTTP-status table
- `newProblem` / `newSubproblem` — pure data factories for [RFC 7807][rfc7807]
  problem documents

### Planned

| Export | Description | Dependencies |
|--------|-------------|--------------|
| `@kagal/acme/utils` | + CSR parsing, cert inspection, ARI cert ID, PEM helpers | + @peculiar/x509, pkijs |
| `@kagal/acme/client` | + Client state machines | /schema, /utils |
| `@kagal/acme/server` | + Server state machines | /schema, /utils |

Client and server will ship as resumable state
machines with JSON-serialisable state and injected
dependencies — the machine will own protocol logic,
the consumer will own persistence, key material, and
policy.

Sub-paths are layered by dependency weight — import
the lightest layer you need:

```text
types          zero deps, type-only contracts
  \
  schema       + valibot — structural validation
    \
    utils      + WebCrypto — decode, validate, verify
    / \
client  server   protocol state machines
```

`/schema` validators return the hand-written types
from `/types`, not Valibot's inferred output.
`/utils` uses `/schema` internally for the
decode → validate → verify pipeline (`parseJWK`,
`exportJWK`).

Encoding contracts cross the layer boundary as
branded strings: `@kagal/acme/types` exports
`Base64url`, `Base64urlAlphabet`, and `PEM`, and every
`/utils` producer and `/schema` validator returns the
brand. `Base64urlAlphabet` is the alphabet-only sibling
of `Base64url` — used for `Challenge.token` (RFC 8555
§8.1), where the wire format constrains characters to
the base64url alphabet but does not carry a byte-framed
length. Plain `string` cannot be assigned to a branded
slot — use a producer, a validator, or the unvalidated
`asBase64url` / `asBase64urlAlphabet` / `asPEM`
accessor at a trust boundary.

Type-only consumers add `@kagal/acme` as a
`devDependency` and import from `/types`.

## Usage

### Types

```typescript
import type {
  Order,
  OrderStatus,
} from '@kagal/acme/types';

// Runtime constants for validation checks
import { OrderStatuses } from '@kagal/acme/types';

if (OrderStatuses.has(raw)) {
  // raw is OrderStatus
}
```

### Schema validation

```typescript
import { validateOrder } from '@kagal/acme/schema';

const result = validateOrder(json);
if (result.success) {
  result.data.status;       // OrderStatus
  result.data.identifiers;  // Identifier[]
} else {
  result.issues;            // validation errors
}
```

Response object schemas use `looseObject` — unknown
fields pass through for forward compatibility.
Request payload schemas use `strictObject` — the
client controls the structure. Decoded JWS headers
use `looseObject` (headers allow additional
parameters) with `ACMERequestHeaderSchema` enforcing
the `jwk` XOR `kid` constraint.

### Problem documents

```typescript
import { newProblem, newSubproblem } from '@kagal/acme/types';

// HTTP status defaults from the URN→HTTP table.
const problem = newProblem(
  'urn:ietf:params:acme:error:rejectedIdentifier',
  'Identifier outside allowed set',
);

// Per-identifier sub-errors (RFC 8555 §6.7.1).
const compound = newProblem(
  'urn:ietf:params:acme:error:compound',
  'Pre-issuance checks failed',
  {
    subproblems: [
      newSubproblem(
        'urn:ietf:params:acme:error:caa',
        { type: 'dns', value: 'forbidden.example' },
        'CAA forbids issuance',
      ),
    ],
  },
);
```

`newProblem` derives the HTTP status from
`errorStatus[urn]` unless `options.status` overrides it
(Boulder reuses some URNs with non-default statuses).
Any top-level URN may carry `subproblems` per RFC 8555
§6.7.1; `compound` is the canonical aggregator.

### Encoding

```typescript
import {
  encodeBase64url,
  getRandom,
  jwkThumbprint,
} from '@kagal/acme/utils';

// Encode raw bytes to base64url (branded `Base64url`).
const sig = encodeBase64url(signatureBytes);

// Random token, base64url-encoded.
const nonce = getRandom(16);

// RFC 7638 SHA-256 JWK thumbprint — 43 chars.
const thumbprint = await jwkThumbprint(accountJWK);
```

## Licence

[MIT][mit]

<!-- references -->
[mit]: ../../LICENCE.txt
[rfc7807]: https://datatracker.ietf.org/doc/html/rfc7807
[types-exports]: #types-exports
