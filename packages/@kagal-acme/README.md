# @kagal/acme

Platform-neutral ACME protocol library (RFC 8555).
Protocol types, Valibot schemas, and WebCrypto-based
utilities.

## Sub-path Exports

### Current

| Export | Description | Dependencies |
|--------|-------------|--------------|
| `@kagal/acme/types` | Interfaces, const tuples, ReadonlySet constants, branded `Base64url` / `Base64urlAlphabet` / `PEM` | none |
| `@kagal/acme/schema` | Valibot validators | valibot |
| `@kagal/acme/utils` | base64url codec, random bytes, JWK thumbprint, JWK export / parse | WebCrypto, jose, /schema |
| `@kagal/acme/client` | Stub — no surface yet | none |
| `@kagal/acme/server` | Stub — no surface yet | none |

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

[MIT](../../LICENCE.txt)
