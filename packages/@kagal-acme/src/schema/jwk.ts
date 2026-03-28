// JWK schema (RFC 7517)

import * as v from 'valibot';

/** Shared optional JWK members (RFC 7517 §4). */
const jwkBase = {
  'kid': v.optional(v.string()),
  'alg': v.optional(v.string()),
  'use': v.optional(v.string()),
  'key_ops': v.optional(v.pipe(
    v.array(v.string()), v.readonly(),
  )),
  'x5u': v.optional(v.string()),
  'x5c': v.optional(v.pipe(
    v.array(v.string()), v.readonly(),
  )),
  'x5t': v.optional(v.string()),
  'x5t#S256': v.optional(v.string()),
};

/**
 * {@link JWK} schema (RFC 7517).
 *
 * @remarks
 * Uses `v.variant` on `kty` to discriminate
 * EC, OKP, and RSA key types. Each variant uses
 * `looseObject` — JWKs may contain additional
 * members (RFC 7517 §4).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7517}
 */
export const JWKSchema = v.variant('kty', [
  v.looseObject({
    kty: v.literal('EC'),
    crv: v.string(),
    x: v.string(),
    y: v.string(),
    ...jwkBase,
  }),
  v.looseObject({
    kty: v.literal('OKP'),
    crv: v.string(),
    x: v.string(),
    ...jwkBase,
  }),
  v.looseObject({
    kty: v.literal('RSA'),
    n: v.string(),
    e: v.string(),
    ...jwkBase,
  }),
]);
