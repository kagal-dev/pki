// Authorization schema (RFC 8555 §7.1.4)

import * as v from 'valibot';

import type { AuthorizationStatus } from '../types/constants/status';
import {
  authorizationStatuses,
} from '../types/constants/status';

import { ChallengeSchema } from './challenge';
import { IdentifierSchema } from './identifier';

/** Statuses handled by their own variant branches. */
const authorizationOtherStatuses = authorizationStatuses.filter(
  (s): s is Exclude<AuthorizationStatus, 'pending' | 'valid'> =>
    s !== 'pending' && s !== 'valid',
);

/** Shared authorisation fields. */
const authorizationBase = {
  identifier: IdentifierSchema,
  challenges: v.array(ChallengeSchema),
  wildcard: v.optional(v.boolean()),
};

/** RFC 3339 timestamp schema — reused on all branches. */
const expiresTimestamp = v.pipe(v.string(), v.isoTimestamp());

/**
 * {@link Authorization} schema — discriminated on
 * `status`.
 *
 * @remarks
 * Uses `looseObject` — unknown fields pass through.
 * `expires` is required when status is `'valid'` and
 * always an RFC 3339 timestamp when present.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.4}
 */
export const AuthorizationSchema = v.variant('status', [
  v.looseObject({
    ...authorizationBase,
    status: v.literal('pending'),
    expires: v.optional(expiresTimestamp),
  }),
  v.looseObject({
    ...authorizationBase,
    status: v.literal('valid'),
    expires: expiresTimestamp,
  }),
  v.looseObject({
    ...authorizationBase,
    status: v.picklist(authorizationOtherStatuses),
    expires: v.optional(expiresTimestamp),
  }),
]);
