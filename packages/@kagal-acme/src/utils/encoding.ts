// Base64url encoding utilities

import { asBase64url, type Base64url } from '../types/encoding';

/**
 * Encode an {@link ArrayBuffer} as a base64url string
 * without padding (RFC 7515 §2).
 *
 * @example
 * ```typescript
 * const bytes = new TextEncoder().encode('Hello');
 * encodeBase64url(bytes.buffer); // 'SGVsbG8' as Base64url
 * ```
 */
export function encodeBase64url(
  buffer: ArrayBuffer,
): Base64url {
  const bytes = new Uint8Array(buffer);
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
    // `atob` output is a binary string of single code
    // units in [0, 255]; `codePointAt` is always
    // defined here. The `?? 0` satisfies the static
    // type (`number | undefined`) without a non-null
    // assertion.
    bytes[i] = binary.codePointAt(i) ?? 0;
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
  return encodeBase64url(bytes.buffer as ArrayBuffer);
}
