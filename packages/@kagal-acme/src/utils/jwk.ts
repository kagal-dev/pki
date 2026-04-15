// JWK utilities — thumbprints (RFC 7638)

import type { Base64url } from '../types/encoding';
import type { JWK } from '../types/jws/jwk';

import { mustMembers } from './assert';
import { encodeBase64url } from './encoding';

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
 * Suitable for use as the `jwk["kid"]` per RFC 7638 §3.1
 * and as the ACME account URL key identifier.
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
      throw new Error(`unsupported JWK kty: ${String(kty)}`);
    }
  }
}
