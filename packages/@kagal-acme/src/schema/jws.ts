// JWS schemas (RFC 7515, RFC 8555)

import * as v from 'valibot';

import {
  Base64urlOrEmptySchema,
  Base64urlSchema,
} from './encoding';
import { JWKSchema } from './jwk';

/**
 * {@link FlattenedJWS} schema (RFC 7515 §7.2.2).
 *
 * @remarks
 * Uses `strictObject` — the three base64url fields
 * are the only expected properties. `payload` may be
 * empty for POST-as-GET requests (RFC 8555 §6.3).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7515#section-7.2.2}
 */
export const FlattenedJWSSchema = v.strictObject({
  protected: Base64urlSchema,
  payload: Base64urlOrEmptySchema,
  signature: Base64urlSchema,
});

/** Shared JWS protected header fields (RFC 7515 §4.1). */
const jwsProtectedHeaderBase = {
  alg: v.string(),
  jwk: v.optional(JWKSchema),
  kid: v.optional(v.string()),
};

/**
 * {@link JWSProtectedHeader} schema (RFC 7515 §4.1).
 *
 * @remarks
 * Uses `looseObject` — JWS headers may contain
 * additional registered or private parameters.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7515#section-4.1}
 */
export const JWSProtectedHeaderSchema = v.looseObject({
  ...jwsProtectedHeaderBase,
});

/**
 * {@link ACMEProtectedHeader} schema (RFC 8555 §6.2).
 *
 * @remarks
 * Uses `looseObject` — extends
 * {@link JWSProtectedHeaderSchema} with ACME-required
 * `nonce` and `url`.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-6.2}
 */
export const ACMEProtectedHeaderSchema = v.looseObject({
  ...jwsProtectedHeaderBase,
  nonce: v.string(),
  url: v.string(),
});

/** Shared ACME request header fields. */
const acmeRequestHeaderBase = {
  alg: v.string(),
  nonce: v.string(),
  url: v.string(),
};

/**
 * {@link ACMERequestHeader} schema (RFC 8555 §6.2).
 *
 * @remarks
 * Enforces `jwk` XOR `kid` — servers MUST reject
 * headers containing both. Uses `looseObject` for
 * header extensibility with a `check` action for
 * mutual exclusion.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-6.2}
 */
export const ACMERequestHeaderSchema = v.pipe(
  v.union([
    v.looseObject({
      ...acmeRequestHeaderBase,
      jwk: JWKSchema,
    }),
    v.looseObject({
      ...acmeRequestHeaderBase,
      kid: v.string(),
    }),
  ]),
  v.check(
    (input) => !('jwk' in input && 'kid' in input),
    'Provide \'jwk\' or \'kid\', not both',
  ),
);
