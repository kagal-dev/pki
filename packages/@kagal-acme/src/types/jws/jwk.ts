// JSON Web Key types (RFC 7517)

import type { Base64url } from '../encoding';

/**
 * EC curves (RFC 7518 §6.2.1.1).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.1}
 */
export const ecCurves = [
  'P-256',
  'P-384',
  'P-521',
] as const;

/**
 * {@link ecCurves} union.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.1}
 */
export type ECCurve = (typeof ecCurves)[number];

/** Runtime set of valid EC curves. */
export const ECCurves: ReadonlySet<ECCurve> =
  new Set(ecCurves);

/**
 * OKP curves (RFC 8037 §2).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8037#section-2}
 */
export const okpCurves = [
  'Ed25519',
  'Ed448',
  'X25519',
  'X448',
] as const;

/**
 * {@link okpCurves} union.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8037#section-2}
 */
export type OKPCurve = (typeof okpCurves)[number];

/** Runtime set of valid OKP curves. */
export const OKPCurves: ReadonlySet<OKPCurve> =
  new Set(okpCurves);

/**
 * Optional JWK members shared by all key types (RFC 7517 §4).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7517#section-4}
 */
export type JWKBase = {
  /** Algorithm (§4.4). */
  'alg'?: string
  /** Key operations (§4.3). */
  'key_ops'?: readonly string[]
  /** Key ID (§4.5). */
  'kid'?: string
  /** Public key use (§4.2). */
  'use'?: string
  /** X.509 certificate chain (§4.7). */
  'x5c'?: readonly string[]
  /** X.509 SHA-1 thumbprint (§4.8). */
  'x5t'?: string
  /** X.509 SHA-256 thumbprint (§4.9). */
  'x5t#S256'?: string
  /** X.509 URL (§4.6). */
  'x5u'?: string
};

/**
 * EC key (RFC 7518 §6.2).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7518#section-6.2}
 */
export type ECJWK = JWKBase & {
  kty: 'EC'

  crv: ECCurve
  x: Base64url
  y: Base64url
};

/**
 * OKP key (RFC 8037 §2).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8037#section-2}
 */
export type OKPJWK = JWKBase & {
  kty: 'OKP'

  crv: OKPCurve
  x: Base64url
};

/**
 * RSA key (RFC 7518 §6.3).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7518#section-6.3}
 */
export type RSAJWK = JWKBase & {
  kty: 'RSA'

  e: Base64url
  n: Base64url
};

/**
 * JWK — discriminated union on `kty`.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7517}
 */
export type JWK = ECJWK | OKPJWK | RSAJWK;
