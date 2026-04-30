# @kagal/taiclock

Platform-neutral handler for `/.well-known/taiclock` —
serves signed [TAI64N][tai64n] timestamps over HTTP for
clients that need authenticated wall-clock time without
running an NTP stack or trusting an unauthenticated TLS
handshake clock.

## Install

```sh
pnpm add @kagal/taiclock
```

## Handler

```typescript
import { newTaiclockHandler, TAI64N_PATH } from '@kagal/taiclock';

const taiclock = newTaiclockHandler();

// Worker fetch handler
export default {
  async fetch(request: Request): Promise<Response> {
    if (new URL(request.url).pathname === TAI64N_PATH) {
      return taiclock(request);
    }
    // ...
  },
};

// Hono route
app.get(TAI64N_PATH, (c) => taiclock(c.req.raw));
```

`newTaiclockHandler()` returns an
`async (request) => Response`. `GET` and `HEAD` succeed
with a fresh 25-byte TAI64N label
(`@<sec-hi><sec-lo><nano>`); other methods return `405`
with `Allow: GET, HEAD`.

Response headers on success:

| Header | Value |
|--------|-------|
| `Content-Type` | `application/tai64n` |
| `Content-Length` | `25` |
| `Cache-Control` | `no-store` |
| `TAI-Leap-Seconds` | decimal count (e.g. `37`), always present |

A request `TAI-Nonce` is echoed verbatim in the
response.

## Signing

```typescript
import {
  newEd25519Signer,
  newTaiclockHandler,
} from '@kagal/taiclock';

const taiclock = newTaiclockHandler({
  selector: '2026q2',
  signer: newEd25519Signer(privateKey),
});
```

`signer` and `selector` are co-required: pass both to
sign, neither for an unsigned handler. Construction
throws if only one is supplied, or if `selector` does
not match `[A-Za-z0-9_-]{1,63}` (DKIM-compatible
single DNS label).

When the request carries `TAI-Nonce` *and* a signer is
configured, the response gains:

- `TAI-Key-Selector: <selector>`
- `TAI-Signature: <base64url>` over the framed
  payload.

The framed payload is:

```text
'taiclock-v1\0' || labelBytes || leapU32BE
              || selectorLen(u8) || selectorBytes
              || nonceBytes
```

- `taiclock-v1\0` — domain-separation tag with
  trailing NUL, so the same key cannot be tricked
  into signing for any other protocol.
- `labelBytes` — the 25 ASCII bytes of the TAI64N
  label.
- `leapU32BE` — leap-seconds count as a 4-byte
  big-endian unsigned integer.
- `selectorLen` / `selectorBytes` — the selector
  length-prefixed by a single byte, so a downgrade
  attacker cannot rewrite `TAI-Key-Selector` without
  invalidating the signature.
- `nonceBytes` — the request nonce, verbatim.

`newEd25519Signer(key: CryptoKey)` is the built-in
signer — pass an Ed25519 private `CryptoKey` with
`'sign'` usage and the response carries a 64-byte
RFC 8032 signature. The `Signer` interface is
HSM/KMS-friendly:

```typescript
interface Signer {
  sign: (message: BufferSource) => Promise<ArrayBuffer>;
}
```

## DNS publication

Publish the public key as a DNS `TXT` record at
`<selector>._taiclock.<host>` (DKIM-style). The same
host that serves `/.well-known/taiclock`. Verifiers
read the selector from the `TAI-Key-Selector` response
header and look up the matching record.

TXT record format (single string, ≤ 255 bytes,
DKIM/DMARC-style tag-value list):

```text
v=tai1; k=ed25519; p=<base64-of-32-raw-pubkey-bytes>
```

| Tag | Value |
|-----|-------|
| `v` | Protocol version. `tai1` for the framing in this README. |
| `k` | Key algorithm. `ed25519` for the only algorithm currently defined. |
| `p` | Public key, standard base64. For Ed25519: 32 raw bytes → 43-44 chars. |

Rotate by publishing a new selector alongside the old
one, switching the handler over to the new selector,
then removing the old TXT once cached responses have
expired. Verifiers cache by selector, so old
signatures stay verifiable until their TXT is removed.

## Verifying

```typescript
import { taiclockSignedPayload } from '@kagal/taiclock';

const response = await fetch(taiclockURL, {
  headers: { 'TAI-Nonce': clientNonce },
});
const label = await response.text();
const leap = Number(response.headers.get('TAI-Leap-Seconds'));
const selector = response.headers.get('TAI-Key-Selector')!;
const sigB64 = response.headers.get('TAI-Signature')!;

// Look up the public key in DNS at
// `${selector}._taiclock.${host}` and parse the
// `p=` tag from the TXT record.
const publicKey = await loadPublicKey(host, selector);

const payload = taiclockSignedPayload(
  label,
  leap,
  selector,
  clientNonce,
);
const valid = await crypto.subtle.verify(
  'Ed25519',
  publicKey,
  base64urlDecode(sigB64),
  payload,
);
```

`taiclockSignedPayload(label, leapSeconds, selector,
nonce)` reconstructs the exact byte sequence the
server signed; the verifier supplies only the public
key and a base64url decoder. Comparing the verifier's
recorded nonce against the response's `TAI-Nonce`
defends against replay.

## TAI64N helpers

The handler uses these primitives internally; they
are re-exported for callers that need raw TAI64N
construction:

| Export | Description |
|--------|-------------|
| `now()` | Current TAI as `{ sec, nano, offset }` |
| `fromUTC(utc)` | `Date.now()`-shaped milliseconds → TAI timestamp |
| `tai64nLabel(t?)` | 25-byte label string for a timestamp (or `now()`) |
| `tai64nLabelFromUTC(utc)` | Shortcut for `tai64nLabel(fromUTC(utc))` |

`fromUTC` applies the constant `TAI_OFFSET` (currently
37 seconds). Historic UTC timestamps spanning a
leap-second boundary need caller-side adjustment —
the constant tracks the present, not history.

## Constants

| Name | Value |
|------|-------|
| `TAI64N_PATH` | `/.well-known/taiclock` |
| `TAI64N_CONTENT_TYPE` | `application/tai64n` |
| `TAI64N_CONTENT_TYPE_VENDOR` | `application/vnd.djb.tai64n` |
| `TAI64N_CONTENT_LENGTH` | `25` |
| `TAI64N_HEADER_KEY_SELECTOR` | `TAI-Key-Selector` |
| `TAI64N_HEADER_LEAP_SECONDS` | `TAI-Leap-Seconds` |
| `TAI64N_HEADER_NONCE` | `TAI-Nonce` |
| `TAI64N_HEADER_SIGNATURE` | `TAI-Signature` |
| `TAI_OFFSET` | `37` |
| `TAI64_EPOCH_HI` | `0x40000000` |

## Licence

[MIT][mit]

<!-- references -->
[mit]: ../../LICENCE.txt
[tai64n]: https://cr.yp.to/libtai/tai64.html
