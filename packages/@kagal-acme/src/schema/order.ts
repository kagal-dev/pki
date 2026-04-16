// Order schema (RFC 8555 §7.1.3)

import * as v from 'valibot';

import { orderStatuses } from '../types/constants/status';

import { IdentifierSchema } from './identifier';
import { ProblemSchema } from './problem';
import { CertIDSchema } from './renewal-info';

/**
 * {@link Order} schema.
 *
 * @remarks
 * Uses `looseObject` — unknown fields pass through.
 * Includes ARI `replaces` (RFC 9773) and Profiles
 * `profile` (draft-ietf-acme-profiles) extensions.
 * `expires`, `notBefore`, and `notAfter` are RFC 3339
 * timestamps; URL-typed fields are validated via the
 * WHATWG `URL` parser.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.3}
 */
export const OrderSchema = v.looseObject({
  status: v.picklist(orderStatuses),
  expires: v.optional(v.pipe(v.string(), v.isoTimestamp())),
  identifiers: v.array(IdentifierSchema),
  notBefore: v.optional(v.pipe(v.string(), v.isoTimestamp())),
  notAfter: v.optional(v.pipe(v.string(), v.isoTimestamp())),
  error: v.optional(ProblemSchema),
  authorizations: v.array(v.pipe(v.string(), v.url())),
  finalize: v.pipe(v.string(), v.url()),
  certificate: v.optional(v.pipe(v.string(), v.url())),
  replaces: v.optional(CertIDSchema),
  profile: v.optional(v.string()),
});
