// JWK utilities — thumbprints (RFC 7638),
// WebCrypto export, generic parse.

import { exportJWK as joseExportJWK } from 'jose';

import type { Base64url, JWK } from '../types';
import { validateJWK } from '../schema';

import { encodeBase64url } from './encoding';
import { mustMembers } from './object';

/**
 * Validate arbitrary input as a {@link JWK} and return
 * the branded value, throwing on failure.
 *
 * @remarks
 * Thin wrapper over `validateJWK` from
 * `@kagal/acme/schema` that converts the
 * {@link ValidationResult} contract into a
 * throw-on-failure one. Use this at trust boundaries
 * where the caller cannot meaningfully handle a
 * validation failure (JSON-parsed stored keys,
 * `WebCrypto.exportKey('jwk', …)` output, etc.).
 *
 * @throws `TypeError` if the input is not a valid JWK —
 *   unknown `kty`, missing required member, non-base64url
 *   coord, etc.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7517}
 */
export function parseJWK(input: unknown): JWK {
  const result = validateJWK(input);
  if (!result.success) {
    throw new TypeError('invalid JWK', { cause: result.issues });
  }
  return result.data;
}

/**
 * Export a {@link CryptoKey} as a branded {@link JWK}.
 *
 * @remarks
 * Delegates to `jose.exportJWK` for the
 * `CryptoKey → JWK` conversion (handles the Node /
 * Workers / browser quirks) and validates the result
 * via {@link parseJWK}. WebCrypto is a trusted producer,
 * but validation ensures the output carries the
 * `Base64url` brand on coord / modulus members rather
 * than relying on an unchecked cast.
 *
 * @throws `TypeError` if the exported JWK fails schema
 *   validation (e.g. an unsupported `kty` slips through
 *   a non-standard WebCrypto implementation).
 *
 * @throws Any `DOMException` WebCrypto raises
 *   (non-extractable key, unsupported algorithm, …) —
 *   propagated unchanged.
 */
export async function exportJWK(key: CryptoKey): Promise<JWK> {
  const raw = await joseExportJWK(key);
  return parseJWK(raw);
}

/**
 * Compute the RFC 7638 SHA-256 thumbprint of a JWK.
 *
 * @returns The hash, base64url-encoded without padding
 *   (43 characters for SHA-256).
 *
 * @remarks
 * Only the required members for each `kty` participate
 * in the hash, ordered lexicographically. Optional base
 * members (`kid`, `alg`, `use`, `key_ops`, `x5*`) and
 * any extension members are excluded — two JWKs that
 * differ only in those fields share a thumbprint.
 *
 * Suitable for use as the JWK-internal `kid` (i.e.
 * `jwk["kid"]`) per RFC 7638 §3.1 — distinct from the
 * outer-JWS `kid` header, which per RFC 8555 §6.2 is the
 * server-issued account URL (the thumbprint does not
 * substitute for it).
 *
 * @throws If `jwk.kty` is anything other than `'EC'`,
 *   `'OKP'`, or `'RSA'`, or if a required thumbprint
 *   member for the declared `kty` is missing, the
 *   wrong type, or the empty string. The `kty` switch
 *   is exhaustive per the {@link JWK} union and the
 *   required members are string-typed, so both throws
 *   only fire on a runtime type-system bypass
 *   (unchecked cast, unsanitised JSON, a producer
 *   returning the wrong shape) — fail loudly instead
 *   of hashing to a garbage thumbprint.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7638}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-6.2}
 *
 * @example
 * ```typescript
 * const kid = await jwkThumbprint({
 *   kty: 'EC',
 *   crv: 'P-256',
 *   x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
 *   y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
 * });
 * // kid: Base64url (43 chars)
 * ```
 */
export async function jwkThumbprint(jwk: JWK): Promise<Base64url> {
  const canonical = canonicalJWK(jwk);
  const bytes = new TextEncoder().encode(JSON.stringify(canonical));
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return encodeBase64url(hash);
}

/**
 * Build the canonical JWK input for thumbprinting:
 * required members only, keys inserted in lexicographic
 * order so `JSON.stringify` emits them sorted.
 *
 * @throws If `jwk.kty` is anything other than `'EC'`,
 *   `'OKP'`, or `'RSA'`, or if a required member for
 *   the declared `kty` is missing, the wrong type, or
 *   empty — the switch is exhaustive per the
 *   {@link JWK} union and the required members are
 *   string-typed, but a runtime type-system bypass
 *   (unchecked cast, unsanitised JSON, etc.) must fail
 *   loudly rather than hash to a garbage thumbprint.
 */
function canonicalJWK(jwk: JWK): Record<string, string> {
  switch (jwk.kty) {
    case 'EC':
      mustMembers(jwk, 'crv', 'x', 'y');
      return { crv: jwk.crv, kty: 'EC', x: jwk.x, y: jwk.y };
    case 'OKP':
      mustMembers(jwk, 'crv', 'x');
      return { crv: jwk.crv, kty: 'OKP', x: jwk.x };
    case 'RSA':
      mustMembers(jwk, 'e', 'n');
      return { e: jwk.e, kty: 'RSA', n: jwk.n };
    default: {
      const kty = (jwk as { kty: unknown }).kty;
      throw new TypeError(
        `unsupported JWK kty: ${String(kty)}`,
      );
    }
  }
}
