# @kagal/acme

Platform-neutral ACME protocol library (RFC 8555).
Client and server as resumable state machines with
injected dependencies.

## Sub-path Exports

| Export | Description | Deps |
|--------|-------------|------|
| `@kagal/acme/types` | Interfaces, const tuples, ReadonlySet constants | none |
| `@kagal/acme/schema` | Valibot validators | valibot |
| `@kagal/acme/utils` | CSR parsing, cert inspection, ARI cert ID | valibot, WebCrypto |
| `@kagal/acme/client` | Client state machines | /schema, /utils (valibot, WebCrypto) |
| `@kagal/acme/server` | Server state machines | /schema, /utils (valibot, WebCrypto) |

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

## Licence

[MIT](../../LICENCE.txt)
