// newAuthz request payload schema (RFC 8555 §7.4.1)

import * as v from 'valibot';

import { StrictIdentifierSchema } from './identifier';

/**
 * {@link NewAuthz} schema (RFC 8555 §7.4.1).
 *
 * @remarks
 * Uses `strictObject` — request payloads have a
 * fixed set of fields.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.4.1}
 */
export const NewAuthzSchema = v.strictObject({
  identifier: StrictIdentifierSchema,
});

/**
 * {@link DeactivateAuthorization} schema
 * (RFC 8555 §7.5.2).
 *
 * @remarks
 * Uses `strictObject` — deactivation sends only
 * `status: 'deactivated'`.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.5.2}
 */
export const DeactivateAuthorizationSchema =
  v.strictObject({
    status: v.literal('deactivated'),
  });
