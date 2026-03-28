// newOrder request payload schema (RFC 8555 §7.4)

import * as v from 'valibot';

import { StrictIdentifierSchema } from './identifier';
import { CertIDSchema } from './renewal-info';

/**
 * {@link NewOrder} schema (RFC 8555 §7.4).
 *
 * @remarks
 * Uses `strictObject` — request payloads have a
 * fixed set of fields. Includes ARI `replaces`
 * (RFC 9773) and Profiles `profile`
 * (draft-ietf-acme-profiles) extensions.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.4}
 */
export const NewOrderSchema = v.strictObject({
  identifiers: v.pipe(
    v.array(StrictIdentifierSchema), v.minLength(1),
  ),
  notBefore: v.optional(v.string()),
  notAfter: v.optional(v.string()),
  profile: v.optional(v.string()),
  replaces: v.optional(CertIDSchema),
});
