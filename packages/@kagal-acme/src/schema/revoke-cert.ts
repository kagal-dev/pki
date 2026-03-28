// revokeCert request payload schema (RFC 8555 §7.6)

import * as v from 'valibot';

import { Base64urlSchema } from './encoding';

/**
 * {@link RevokeCert} schema (RFC 8555 §7.6).
 *
 * @remarks
 * Uses `strictObject` — only `certificate` and
 * optional `reason` are expected.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.6}
 */
export const RevokeCertSchema = v.strictObject({
  certificate: Base64urlSchema,
  reason: v.optional(v.pipe(
    v.number(),
    v.integer(),
    v.picklist([0, 1, 2, 3, 4, 5, 6, 8, 9, 10]),
  )),
});
