// Challenge schemas (RFC 8555 §7.1.5, RFC 8737)

import * as v from 'valibot';

import {
  challengeStatuses,
} from '../types/constants/status';

import { Base64urlAlphabetSchema } from './encoding';
import { ProblemSchema } from './problem';

/**
 * Minimum base64url-alphabet length for a challenge
 * token.
 *
 * @remarks
 * RFC 8555 §8.1 requires ≥ 128 bits of entropy.
 * Base64url encodes 6 bits per character, so 128
 * bits → ⌈128 / 6⌉ = 22 unpadded characters.
 */
const minChallengeTokenLength = 22;

/**
 * Challenge token schema — base64url-alphabet string
 * carrying ≥ 128 bits of entropy (RFC 8555 §8.1).
 *
 * @remarks
 * Output is branded {@link Base64urlAlphabet} — the
 * token is alphabet-constrained but not byte-framed,
 * so it does not round-trip through
 * `decodeBase64url`. See {@link Base64urlAlphabet} vs
 * {@link Base64url} for the distinction.
 */
const ChallengeTokenSchema = v.pipe(
  Base64urlAlphabetSchema,
  v.minLength(minChallengeTokenLength),
);

/**
 * Shared challenge fields.
 *
 * @remarks
 * `url` is an operation URL; `validated` is an RFC
 * 3339 timestamp; `token` is a base64url-alphabet
 * string ≥ 22 characters (128 bits of entropy) per
 * RFC 8555 §8.1, outputting the branded
 * {@link Base64urlAlphabet} type.
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
