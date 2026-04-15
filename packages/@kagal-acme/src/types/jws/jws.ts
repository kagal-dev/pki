// JWS types (RFC 7515, RFC 8555)

import type { Base64url } from '../encoding';
import type { JWK } from './jwk';

/**
 * Flattened JWS Serialization (RFC 7515 §7.2.2).
 *
 * @remarks
 * ACME uses the flattened serialisation exclusively —
 * compact and general forms are not used. `payload`
 * may be empty for POST-as-GET requests (RFC 8555
 * §6.3).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7515#section-7.2.2}
 */
export interface FlattenedJWS {
  /** Base64url-encoded protected header. */
  protected: Base64url

  /** Base64url-encoded payload (empty for POST-as-GET). */
  payload: '' | Base64url
  /** Base64url-encoded signature. */
  signature: Base64url
};

/**
 * JWS protected header (RFC 7515 §4.1).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7515#section-4.1}
 */
export interface JWSProtectedHeader {
  /** Signature algorithm (e.g. 'ES256', 'EdDSA'). */
  alg: string
  /** JSON Web Key (RFC 7515 §4.1.3). */
  jwk?: JWK
  /** Key ID (RFC 7515 §4.1.4). */
  kid?: string
};

/**
 * ACME protected header fields (RFC 8555 §6.2).
 *
 * @remarks
 * Extends {@link JWSProtectedHeader} with ACME-required
 * `nonce` and `url`. Inner JWS objects (EAB, key change)
 * omit `nonce` and use {@link JWSProtectedHeader} directly.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-6.2}
 */
export interface ACMEProtectedHeader
  extends JWSProtectedHeader {
  /** Anti-replay nonce (RFC 8555 §6.5). */
  nonce: string
  /** Request URL (RFC 8555 §6.4). */
  url: string
};

/**
 * Outer ACME request header with `jwk` XOR `kid`.
 *
 * @remarks
 * `jwk` for newAccount and revokeCert-by-cert-key;
 * `kid` (account URL) for all other requests.
 * Servers MUST reject headers containing both.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-6.2}
 */
export type ACMERequestHeader =
  ACMEProtectedHeader & {
    /** Account public key. */
    jwk: JWK
    kid?: never
  } |
  ACMEProtectedHeader & {
    jwk?: never
    /** Account URL. */
    kid: string
  };
