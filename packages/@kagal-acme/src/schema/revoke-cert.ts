// revokeCert request payload schema (RFC 8555 §7.6)

import * as v from 'valibot';

import { crlReasonCodes } from '../types';

import { Base64urlSchema } from './encoding';

/**
 * {@link RevokeCert} schema (RFC 8555 §7.6).
 *
 * @remarks
 * Uses `strictObject` — only `certificate` and
 * optional `reason` are expected. `reason` picks
 * from the {@link crlReasonCodes} tuple so the
 * runtime values stay locked to the
 * {@link CRLReasonCode} type (RFC 5280 §5.3.1;
 * code 7 is reserved and excluded).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.6}
 */
export const RevokeCertSchema = v.strictObject({
  certificate: Base64urlSchema,
  reason: v.optional(v.picklist(crlReasonCodes)),
});
