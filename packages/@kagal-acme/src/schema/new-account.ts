// newAccount request payload schema (RFC 8555 §7.3)

import * as v from 'valibot';

import { FlattenedJWSSchema } from './jws';

/**
 * {@link NewAccount} schema (RFC 8555 §7.3).
 *
 * @remarks
 * Uses `strictObject` — request payloads have a
 * fixed set of fields.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.3}
 */
export const NewAccountSchema = v.strictObject({
  contact: v.optional(v.array(v.string())),
  termsOfServiceAgreed: v.optional(v.boolean()),
  onlyReturnExisting: v.optional(v.boolean()),
  externalAccountBinding: v.optional(
    FlattenedJWSSchema,
  ),
});

/**
 * {@link DeactivateAccount} schema
 * (RFC 8555 §7.3.6).
 *
 * @remarks
 * Uses `strictObject` — deactivation sends only
 * `status: 'deactivated'`.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.6}
 */
export const DeactivateAccountSchema =
  v.strictObject({
    status: v.literal('deactivated'),
  });
