// JWS schemas (RFC 7515, RFC 8555)

import * as v from 'valibot';

import { acmeSignAlgorithms, jwsAlgorithms } from '../types';

import {
  Base64urlOrEmptySchema,
  Base64urlSchema,
} from './encoding';
import { JWKSchema } from './jwk';

/**
 * {@link ACMESignAlgorithm} schema (RFC 8555 §6.2).
 *
 * @remarks
 * Picklist of ACME outer-JWS signature algorithms —
 * the asymmetric subset of {@link jwsAlgorithms}. RFC
 * 8555 §6.2 forbids MAC-based algorithms (`HS*`) on
 * the outer JWS; those appear only in EAB inner JWS
 * (§7.3.4), validated separately via
 * {@link JWSProtectedHeaderSchema}. Composed by
 * {@link ACMEProtectedHeaderSchema} and
 * {@link ACMERequestHeaderSchema}; exposed
 * standalone so callers can route a structurally
 * unsupported `alg` to RFC 8555 §6.7
 * `badSignatureAlgorithm` before the full header
 * schema runs (e.g. inside `parseJWS`).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-6.2}
 */
export const ACMESignAlgorithmSchema =
  v.picklist(acmeSignAlgorithms);

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
  alg: v.picklist(jwsAlgorithms),
  jwk: v.optional(JWKSchema),
  kid: v.optional(v.pipe(v.string(), v.minLength(1))),
};

/**
 * {@link JWSProtectedHeader} schema (RFC 7515 §4.1).
 *
 * @remarks
 * Uses `looseObject` — JWS headers may contain
 * additional registered or private parameters.
 * `alg` is restricted to the JWS registry (minus
 * `none`) — {@link jwsAlgorithms}. Used for inner
 * JWS objects only (EAB, key-change); the outer
 * ACME request uses
 * {@link ACMEProtectedHeaderSchema}.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7515#section-4.1}
 */
export const JWSProtectedHeaderSchema = v.looseObject({
  ...jwsProtectedHeaderBase,
});

/** Shared ACME outer-JWS protected header fields. */
const acmeProtectedHeaderBase = {
  alg: ACMESignAlgorithmSchema,
  jwk: v.optional(JWKSchema),
  kid: v.optional(v.pipe(v.string(), v.url())),
  nonce: Base64urlSchema,
  url: v.pipe(v.string(), v.url()),
};

/**
 * {@link ACMEProtectedHeader} schema (RFC 8555 §6.2).
 *
 * @remarks
 * Uses `looseObject` — extends
 * {@link JWSProtectedHeaderSchema} with ACME-required
 * `nonce` and `url`. `alg` narrows to
 * {@link acmeSignAlgorithms} (asymmetric only); §6.2
 * forbids MAC-based algorithms on the outer JWS.
 * `nonce` validates as non-empty base64url per §6.5.
 * `url` and (optional) `kid` validate as URLs.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-6.2}
 */
export const ACMEProtectedHeaderSchema = v.looseObject({
  ...acmeProtectedHeaderBase,
});

/** Shared ACME request header fields. */
const acmeRequestHeaderBase = {
  alg: ACMESignAlgorithmSchema,
  nonce: Base64urlSchema,
  url: v.pipe(v.string(), v.url()),
};

/**
 * {@link ACMERequestHeader} schema (RFC 8555 §6.2).
 *
 * @remarks
 * Enforces `jwk` XOR `kid` — servers MUST reject
 * headers containing both. Uses `looseObject` for
 * header extensibility with a `check` action for
 * mutual exclusion. `kid`, when present, must be a
 * URL (the account URL per §6.2).
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
      kid: v.pipe(v.string(), v.url()),
    }),
  ]),
  v.check(
    (input) => !('jwk' in input && 'kid' in input),
    'Provide \'jwk\' or \'kid\', not both',
  ),
);
