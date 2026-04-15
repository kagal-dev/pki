# @kagal/acme

Platform-neutral ACME protocol library (RFC 8555).
Client and server as resumable state machines with
injected dependencies.

## Sub-path Exports

### Current

| Export | Description | Dependencies |
|--------|-------------|--------------|
| `@kagal/acme/types` | Interfaces, const tuples, ReadonlySet constants, branded `Base64url` / `PEM` | none |
| `@kagal/acme/schema` | Valibot validators | valibot |
| `@kagal/acme/utils` | base64url encode/decode, random bytes, JWK thumbprint | WebCrypto |

### Planned

| Export | Description | Dependencies |
|--------|-------------|--------------|
| `@kagal/acme/utils` | CSR parsing, cert inspection, ARI cert ID, PEM helpers | + valibot, @peculiar/x509, pkijs |
| `@kagal/acme/client` | Client state machines | /schema, /utils |
| `@kagal/acme/server` | Server state machines | /schema, /utils |

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
`/utils` will use `/schema` internally for the
decode → validate → verify pipeline.

Encoding contracts cross the layer boundary as
branded strings: `@kagal/acme/types` exports
`Base64url` and `PEM`, and every `/utils` producer
and `/schema` validator returns the brand. Plain
`string` cannot be assigned to a branded slot —
use a producer, a validator, or the unvalidated
`asBase64url` / `asPEM` accessor at a trust
boundary.

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
