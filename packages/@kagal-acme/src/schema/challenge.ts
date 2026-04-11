// Challenge schemas (RFC 8555 §7.1.5, RFC 8737)

import * as v from 'valibot';

import {
  challengeStatuses,
} from '../types/constants/status';

import { ProblemSchema } from './problem';

/** Shared challenge fields. */
const challengeBase = {
  url: v.string(),
  status: v.picklist(challengeStatuses),
  validated: v.optional(v.string()),
  error: v.optional(ProblemSchema),
  token: v.string(),
};

/**
 * {@link Challenge} schema — discriminated on `type`.
 *
 * @remarks
 * Uses `looseObject` — unknown fields pass through.
 * The union is closed: unknown challenge types fail
 * validation. Consumers must upgrade to support new
 * challenge types from future RFCs.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.5}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8737}
 */
export const ChallengeSchema = v.variant('type', [
  v.looseObject({
    ...challengeBase,
    type: v.literal('dns-01'),
  }),
  v.looseObject({
    ...challengeBase,
    type: v.literal('http-01'),
  }),
  v.looseObject({
    ...challengeBase,
    type: v.literal('tls-alpn-01'),
  }),
]);
