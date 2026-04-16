// Challenge schemas (RFC 8555 §7.1.5, RFC 8737)

import * as v from 'valibot';

import {
  challengeStatuses,
} from '../types/constants/status';

import { Base64urlSchema } from './encoding';
import { ProblemSchema } from './problem';

/**
 * Minimum base64url length for a challenge token.
 *
 * @remarks
 * RFC 8555 §8.1 requires ≥ 128 bits of entropy.
 * Base64url encodes 6 bits per character, so 128
 * bits → ⌈128 / 6⌉ = 22 unpadded characters.
 */
const minChallengeTokenLength = 22;

/**
 * {@link Base64url} token carrying ≥ 128 bits of
 * entropy (RFC 8555 §8.1).
 */
const ChallengeTokenSchema = v.pipe(
  Base64urlSchema,
  v.minLength(minChallengeTokenLength),
);

/**
 * Shared challenge fields.
 *
 * @remarks
 * `url` is an operation URL; `validated` is an RFC
 * 3339 timestamp; `token` is base64url per RFC 8555
 * §8.1 with a minimum 22-character length (128 bits
 * of entropy) and outputs the branded
 * {@link Base64url} type.
 */
const challengeBase = {
  url: v.pipe(v.string(), v.url()),
  status: v.picklist(challengeStatuses),
  validated: v.optional(v.pipe(v.string(), v.isoTimestamp())),
  error: v.optional(ProblemSchema),
  token: ChallengeTokenSchema,
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
