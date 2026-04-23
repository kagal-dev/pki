// keyChange inner payload schema (RFC 8555 §7.3.5)

import * as v from 'valibot';

import { JWKSchema } from './jwk';

/**
 * {@link KeyChange} schema (RFC 8555 §7.3.5).
 *
 * @remarks
 * Uses `strictObject` — the inner JWS payload has
 * exactly two fields. `account` is the account URL
 * (§7.3.5 binds the new key to that URL, so a URL
 * is the only sensible value).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.5}
 */
export const KeyChangeSchema = v.strictObject({
  account: v.pipe(v.string(), v.url()),
  oldKey: JWKSchema,
});
