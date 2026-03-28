// JSON Web Key types (RFC 7517)

/**
 * Optional JWK members shared by all key types (RFC 7517 §4).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7517#section-4}
 */
export type JWKBase = {
  /** Key ID (§4.5). */
  'kid'?: string
  /** Algorithm (§4.4). */
  'alg'?: string
  /** Public key use (§4.2). */
  'use'?: string
  /** Key operations (§4.3). */
  'key_ops'?: readonly string[]
  /** X.509 URL (§4.6). */
  'x5u'?: string
  /** X.509 certificate chain (§4.7). */
  'x5c'?: readonly string[]
  /** X.509 SHA-1 thumbprint (§4.8). */
  'x5t'?: string
  /** X.509 SHA-256 thumbprint (§4.9). */
  'x5t#S256'?: string
};

/**
 * EC key (RFC 7518 §6.2).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7518#section-6.2}
 */
export type ECJWK = JWKBase & {
  kty: 'EC'
  crv: string
  x: string
  y: string
};

/**
 * OKP key (RFC 8037 §2).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8037#section-2}
 */
export type OKPJWK = JWKBase & {
  kty: 'OKP'
  crv: string
  x: string
};

/**
 * RSA key (RFC 7518 §6.3).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7518#section-6.3}
 */
export type RSAJWK = JWKBase & {
  kty: 'RSA'
  n: string
  e: string
};

/**
 * JWK — discriminated union on `kty`.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7517}
 */
export type JWK = ECJWK | OKPJWK | RSAJWK;
