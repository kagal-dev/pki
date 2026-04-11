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
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.3}
 */
export const OrderSchema = v.looseObject({
  status: v.picklist(orderStatuses),
  expires: v.optional(v.string()),
  identifiers: v.array(IdentifierSchema),
  notBefore: v.optional(v.string()),
  notAfter: v.optional(v.string()),
  error: v.optional(ProblemSchema),
  authorizations: v.array(v.string()),
  finalize: v.string(),
  certificate: v.optional(v.string()),
  replaces: v.optional(CertIDSchema),
  profile: v.optional(v.string()),
});
