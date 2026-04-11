// Finalize request payload schema (RFC 8555 §7.4)

import * as v from 'valibot';

import { Base64urlSchema } from './encoding';

/**
 * {@link Finalize} schema (RFC 8555 §7.4).
 *
 * @remarks
 * Uses `strictObject` — the CSR is the only
 * expected field. Validates base64url encoding.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.4}
 */
export const FinalizeSchema = v.strictObject({
  csr: Base64urlSchema,
});
