// JWK schema (RFC 7517)

import * as v from 'valibot';

import { ecCurves, okpCurves } from '../types';

import { Base64urlSchema } from './encoding';

/** Shared optional JWK members (RFC 7517 §4). */
const jwkBase = {
  'kid': v.optional(v.string()),
  'alg': v.optional(v.string()),
  'use': v.optional(v.string()),
  'key_ops': v.optional(v.array(v.string())),
  'x5u': v.optional(v.string()),
  'x5c': v.optional(v.array(v.string())),
  'x5t': v.optional(v.string()),
  'x5t#S256': v.optional(v.string()),
};

/**
 * {@link JWK} schema (RFC 7517).
 *
 * @remarks
 * Uses `v.variant` on `kty` to discriminate EC, OKP,
 * and RSA key types. Each variant uses `looseObject` —
 * JWKs may contain additional members (RFC 7517 §4).
 *
 * `crv` is a picklist restricted to the registered
 * curves per key type. Coordinate/modulus members
 * (`x`, `y`, `n`, `e`) go through
 * {@link Base64urlSchema}: non-empty, URL-safe
 * alphabet, length `% 4 !== 1`. Optional base members
 * (`alg`, `use`, `key_ops`, `x5*`) stay free-form
 * strings — RFC 7517 permits unregistered values.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7517}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7518#section-6}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8037#section-2}
 */
export const JWKSchema = v.variant('kty', [
  v.looseObject({
    kty: v.literal('EC'),
    crv: v.picklist(ecCurves),
    x: Base64urlSchema,
    y: Base64urlSchema,
    ...jwkBase,
  }),
  v.looseObject({
    kty: v.literal('OKP'),
    crv: v.picklist(okpCurves),
    x: Base64urlSchema,
    ...jwkBase,
  }),
  v.looseObject({
    kty: v.literal('RSA'),
    n: Base64urlSchema,
    e: Base64urlSchema,
    ...jwkBase,
  }),
]);
