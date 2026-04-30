import type { Signer } from './signer';
import {
  TAI64N_CONTENT_LENGTH,
  TAI64N_CONTENT_TYPE,
  TAI64N_HEADER_KEY_SELECTOR,
  TAI64N_HEADER_LEAP_SECONDS,
  TAI64N_HEADER_NONCE,
  TAI64N_HEADER_SIGNATURE,
  TAI_OFFSET,
} from './const';
import { tai64nLabel } from './utils';

const SELECTOR_PATTERN = /^[\dA-Za-z_-]{1,63}$/;

const textEncoder = new TextEncoder();

/**
 * Domain-separation tag prepended to every signed
 * payload. Versioned so a v2 protocol can use the same
 * key without colliding with v1 signatures, and
 * NUL-terminated so the boundary between tag and
 * label is unambiguous.
 */
const DOMAIN_SEPARATOR = textEncoder.encode('taiclock-v1\0');

const asBytes = (source: BufferSource): Uint8Array => {
  if (source instanceof Uint8Array) {
    return source;
  }
  if (ArrayBuffer.isView(source)) {
    return new Uint8Array(
      source.buffer,
      source.byteOffset,
      source.byteLength,
    );
  }
  return new Uint8Array(source);
};

const encodeBase64url = (source: BufferSource): string => {
  // Spread is safe for the 64-byte signatures handled
  // here; revisit if larger payloads ever land.
  const bytes = asBytes(source);
  return btoa(String.fromCodePoint(...bytes))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/, '');
};

/**
 * Compose the byte sequence covered by a TAI-Signature.
 *
 * @param label - the 25-byte TAI64N label string the
 *   server is returning
 * @param leapSeconds - the leap-seconds count the server
 *   advertises in `TAI-Leap-Seconds`
 * @param selector - the key selector the server
 *   advertises in `TAI-Key-Selector`; verifiers use
 *   this to look up the public key in DNS at
 *   `<selector>._taiclock.<host>`
 * @param nonce - the client-supplied nonce, echoed
 *   verbatim in `TAI-Nonce`
 * @returns the byte sequence verifiers reconstruct
 *   from the response and pass to their public-key
 *   verify routine. The framing is the
 *   domain-separation tag (`taiclock-v1` plus a
 *   trailing NUL byte), then the label bytes, then
 *   the leap-seconds count as a 4-byte big-endian
 *   unsigned integer, then a 1-byte selector length,
 *   then the selector bytes, then the nonce bytes.
 *
 * @remarks
 * Binding the selector into the signed payload stops a
 * downgrade attacker from rewriting `TAI-Key-Selector`
 * to point at a compromised or weaker key — the
 * signature would no longer verify under that key.
 * `leapSeconds` is encoded as a 4-byte big-endian
 * unsigned integer; the selector is length-prefixed by
 * a single byte (selectors are ≤ 63 chars per
 * {@link newTaiclockHandler}'s validation).
 */
export const taiclockSignedPayload = (
  label: string,
  leapSeconds: number,
  selector: string,
  nonce: string,
): ArrayBuffer => {
  const labelBytes = textEncoder.encode(label);
  const selectorBytes = textEncoder.encode(selector);
  const nonceBytes = textEncoder.encode(nonce);

  const buffer = new ArrayBuffer(
    DOMAIN_SEPARATOR.length +
    labelBytes.length +
    4 +
    1 +
    selectorBytes.length +
    nonceBytes.length,
  );
  const view = new Uint8Array(buffer);

  let offset = 0;
  view.set(DOMAIN_SEPARATOR, offset);
  offset += DOMAIN_SEPARATOR.length;
  view.set(labelBytes, offset);
  offset += labelBytes.length;
  new DataView(buffer).setUint32(offset, leapSeconds, false);
  offset += 4;
  view[offset] = selectorBytes.length;
  offset += 1;
  view.set(selectorBytes, offset);
  offset += selectorBytes.length;
  view.set(nonceBytes, offset);

  return buffer;
};

/**
 * Configuration for {@link newTaiclockHandler}.
 *
 * @remarks
 * `signer` and `selector` are co-required: pass both
 * to enable authenticated responses, or neither for
 * an unsigned handler. Passing only one is rejected
 * at construction time — without the selector
 * verifiers cannot find the key in DNS, and a
 * selector without a signer is a misconfiguration.
 */
export interface TaiclockHandlerConfig {
  /**
   * Key selector advertised in the `TAI-Key-Selector`
   * response header and bound into the signed payload.
   * Verifiers look up the public key at
   * `<selector>._taiclock.<host>` in DNS.
   *
   * Must match `[A-Za-z0-9_-]{1,63}` (a single DNS
   * label using DKIM-compatible characters); rotate
   * by changing the selector and publishing a new TXT
   * record.
   */
  selector?: string

  /**
   * {@link Signer} that produces `TAI-Signature` over
   * the framed payload from {@link taiclockSignedPayload}.
   * Without a signer the nonce is still echoed but the
   * response is unsigned.
   */
  signer?: Signer
}

/**
 * Build a handler for `/.well-known/taiclock`.
 *
 * @param config - optional {@link TaiclockHandlerConfig}
 * @returns an `async (request) => Response` callable
 *   directly as a Web `fetch` handler or as a Hono
 *   route handler.
 *
 * @throws TypeError if `signer` and `selector` are not
 *   both set or both unset, or if `selector` does not
 *   match `[A-Za-z0-9_-]{1,63}`.
 *
 * @remarks
 * Behaviour:
 *
 * - `GET` / `HEAD` — body is a fresh 25-byte TAI64N
 *   label. Response headers: Content-Type
 *   `application/tai64n`, Content-Length `25`,
 *   Cache-Control `no-store`, plus `TAI-Leap-Seconds`
 *   carrying the current count.
 * - Any other method — `405 Method Not Allowed` with
 *   `Allow: GET, HEAD`.
 * - Request `TAI-Nonce` — the value is echoed verbatim
 *   in the response.
 * - Request `TAI-Nonce` *and* `signer` configured —
 *   adds `TAI-Key-Selector` and `TAI-Signature`
 *   (base64url) over the bytes produced by
 *   {@link taiclockSignedPayload}. The
 *   domain-separation tag means the same key cannot
 *   be tricked into producing valid signatures for
 *   other protocols.
 *
 * The corresponding public key is expected to be
 * published out-of-band as a DNS TXT record at
 * `<selector>._taiclock.<host>` — verifiers fetch the
 * key by selector so the operator can rotate keys by
 * publishing a new selector while the old one is
 * still cached.
 *
 * @see {@link https://cr.yp.to/libtai/tai64.html} for
 *   TAI64N format
 */
export const newTaiclockHandler = (
  config: TaiclockHandlerConfig = {},
): ((request: Request) => Promise<Response>) => {
  const { selector, signer } = config;

  if ((signer === undefined) !== (selector === undefined)) {
    throw new TypeError(
      'newTaiclockHandler: signer and selector must be set together',
    );
  }
  if (selector !== undefined && !SELECTOR_PATTERN.test(selector)) {
    throw new TypeError(
      `newTaiclockHandler: selector must match ${SELECTOR_PATTERN.source}`,
    );
  }

  return async (request) => {
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return new Response(undefined, {
        status: 405,
        headers: { allow: 'GET, HEAD' },
      });
    }

    const label = tai64nLabel();
    const nonce = request.headers.get(TAI64N_HEADER_NONCE);

    const headers = new Headers({
      'cache-control': 'no-store',
      'content-length': String(TAI64N_CONTENT_LENGTH),
      'content-type': TAI64N_CONTENT_TYPE,
      [TAI64N_HEADER_LEAP_SECONDS]: String(TAI_OFFSET),
    });

    if (nonce !== null) {
      headers.set(TAI64N_HEADER_NONCE, nonce);

      if (signer !== undefined && selector !== undefined) {
        const message = taiclockSignedPayload(
          label,
          TAI_OFFSET,
          selector,
          nonce,
        );
        const signature = await signer.sign(message);
        headers.set(TAI64N_HEADER_KEY_SELECTOR, selector);
        headers.set(TAI64N_HEADER_SIGNATURE, encodeBase64url(signature));
      }
    }

    const body = request.method === 'HEAD' ? undefined : label;
    return new Response(body, { status: 200, headers });
  };
};
