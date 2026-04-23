// Base64url encoding utilities

import { asBase64url, type Base64url } from '../types/encoding';

/**
 * Normalise a {@link BufferSource} to a {@link Uint8Array}
 * view without copying.
 *
 * @remarks
 * Accepting `BufferSource` rather than `ArrayBuffer`
 * keeps `.buffer as ArrayBuffer` casts out of callers —
 * `TypedArray.buffer` widens to `ArrayBufferLike`
 * (`SharedArrayBuffer` included), so caller-side casts
 * are both common and hazardous.
 */
function asBytes(source: BufferSource): Uint8Array {
  if (source instanceof Uint8Array) {
    return source;
  }
  if (ArrayBuffer.isView(source)) {
    return new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
  }
  return new Uint8Array(source);
}

/**
 * Encode a byte sequence as a base64url string without
 * padding (RFC 7515 §2).
 *
 * @remarks
 * Accepts any {@link BufferSource} — an `ArrayBuffer`
 * (e.g. `crypto.subtle.digest` output) or a typed-array
 * view (e.g. `new Uint8Array(n)` from
 * `crypto.getRandomValues`). The alternative —
 * `ArrayBuffer` only — forced `.buffer as ArrayBuffer`
 * casts at call sites because `TypedArray.buffer`
 * widens to `ArrayBufferLike` (`SharedArrayBuffer`
 * included). Normalising here instead keeps the casts
 * out of caller code.
 *
 * @example
 * ```typescript
 * const bytes = new TextEncoder().encode('Hello');
 * encodeBase64url(bytes); // 'SGVsbG8' as Base64url
 * ```
 */
export function encodeBase64url(
  source: BufferSource,
): Base64url {
  const bytes = asBytes(source);
  // `String.fromCodePoint(...bytes)` spreads bytes as
  // call arguments — V8's argument-limit (~100K) caps
  // the safe buffer size. Fine for signatures, hashes,
  // CSRs; revisit with a chunked impl if cert chains
  // ever land here.
  return asBase64url(
    btoa(String.fromCodePoint(...bytes))
      .replaceAll('+', '-')
      .replaceAll('/', '_')
      .replace(/=+$/, ''),
  );
}

/**
 * Decode a base64url string to an {@link ArrayBuffer}.
 *
 * @example
 * ```typescript
 * const bytes = decodeBase64url('SGVsbG8');
 * new TextDecoder().decode(bytes); // 'Hello'
 * ```
 */
export function decodeBase64url(input: string): ArrayBuffer {
  // Swap URL-safe chars back to standard base64.
  // `atob` is forgiving about missing `=` padding
  // (HTML-spec forgiving-base64), so no re-pad needed.
  const standard = input
    .replaceAll('-', '+')
    .replaceAll('_', '/');
  const binary = atob(standard);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    // `atob` output bytes are ≤ 0xFF — no surrogates.
    // eslint-disable-next-line unicorn/prefer-code-point
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer as ArrayBuffer;
}

/**
 * Generate `length` random bytes as a base64url string.
 *
 * @param length - number of bytes to generate; must be
 *   a positive safe integer ≤ 65 536 (the WebCrypto
 *   `getRandomValues` quota).
 * @throws RangeError if `length` is not a positive
 *   safe integer or exceeds the 65 536-byte quota.
 *
 * @example
 * ```typescript
 * // 128 bits of entropy, 22-char Base64url.
 * const nonce = getRandom(16);
 * ```
 */
export function getRandom(length: number): Base64url {
  if (!Number.isSafeInteger(length) || length <= 0) {
    throw new RangeError(
      'length must be a positive safe integer',
    );
  }
  if (length > 65_536) {
    throw new RangeError(
      'length must be at most 65 536 bytes',
    );
  }
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return encodeBase64url(bytes);
}
