// ACME JWS signature algorithms (RFC 7518 §3.1, RFC 8037 §3.1)

/**
 * JWS signature algorithms.
 *
 * @remarks
 * Covers the RFC 7518 §3.1 JSON Web Algorithms
 * registry plus RFC 8037 §3.1's EdDSA entry. The
 * `none` algorithm is deliberately excluded —
 * ACME JWS objects always carry a signature, so a
 * header with `alg: 'none'` is never acceptable in
 * this library. MAC-based algorithms (`HS*`) are
 * valid for External Account Binding (RFC 8555
 * §7.3.4) but MUST NOT appear on the outer ACME
 * request; see {@link acmeSignAlgorithms} for the
 * asymmetric-only subset enforced on the outer JWS.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7518#section-3.1}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8037#section-3.1}
 */
export const jwsAlgorithms = [
  'EdDSA', // RFC 8037
  'ES256', // ECDSA P-256 + SHA-256
  'ES384', // ECDSA P-384 + SHA-384
  'ES512', // ECDSA P-521 + SHA-512
  'HS256', // HMAC SHA-256 — EAB only
  'HS384', // HMAC SHA-384
  'HS512', // HMAC SHA-512
  'PS256', // RSASSA-PSS + SHA-256
  'PS384', // RSASSA-PSS + SHA-384
  'PS512', // RSASSA-PSS + SHA-512
  'RS256', // RSASSA-PKCS1-v1_5 + SHA-256
  'RS384', // RSASSA-PKCS1-v1_5 + SHA-384
  'RS512', // RSASSA-PKCS1-v1_5 + SHA-512
] as const;

/**
 * {@link jwsAlgorithms} union.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7518#section-3.1}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8037#section-3.1}
 */
export type JWSAlgorithm = (typeof jwsAlgorithms)[number];

/** Runtime set of valid JWS algorithms. */
export const JWSAlgorithms: ReadonlySet<JWSAlgorithm> =
  new Set(jwsAlgorithms);

/**
 * ACME outer-JWS signature algorithms — asymmetric
 * subset of {@link jwsAlgorithms}.
 *
 * @remarks
 * RFC 8555 §6.2 forbids MAC-based algorithms on the
 * outer JWS of an ACME request: the server needs the
 * client's public key to authenticate the request,
 * and a MAC shared secret can't establish that.
 * `HS*` appears only in EAB inner JWS (§7.3.4),
 * validated separately via
 * {@link JWSProtectedHeaderSchema}.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-6.2}
 */
export const acmeSignAlgorithms = [
  'EdDSA',
  'ES256',
  'ES384',
  'ES512',
  'PS256',
  'PS384',
  'PS512',
  'RS256',
  'RS384',
  'RS512',
] as const;

/**
 * {@link acmeSignAlgorithms} union.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-6.2}
 */
export type ACMESignAlgorithm =
  (typeof acmeSignAlgorithms)[number];

/** Runtime set of ACME outer-JWS signature algorithms. */
export const ACMESignAlgorithms: ReadonlySet<ACMESignAlgorithm> =
  new Set(acmeSignAlgorithms);
