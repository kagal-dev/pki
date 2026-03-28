// ARI extension schemas (RFC 9773)

import * as v from 'valibot';

/** Suggested renewal window (start/end RFC 3339 timestamps). */
const SuggestedWindowSchema = v.pipe(
  v.strictObject({
    start: v.pipe(v.string(), v.isoTimestamp()),
    end: v.pipe(v.string(), v.isoTimestamp()),
  }),
  v.check(
    (input) => Date.parse(input.start) < Date.parse(input.end),
    '\'start\' must be before \'end\'',
  ),
);

/**
 * {@link RenewalInfo} schema (RFC 9773 §4).
 *
 * @remarks
 * Uses `looseObject` — unknown fields pass through.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc9773#section-4}
 */
export const RenewalInfoSchema = v.looseObject({
  suggestedWindow: SuggestedWindowSchema,
  explanationURL: v.optional(v.string()),
});

/**
 * ARI certID format:
 * `base64url(AKI) + "." + base64url(Serial)`.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc9773#section-4.1}
 */
const certIDPattern = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

/**
 * {@link CertID} schema (RFC 9773 §4.1).
 *
 * @remarks
 * Validates the `base64url(AKI).base64url(Serial)`
 * format used to identify certificates in ARI.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc9773#section-4.1}
 */
export const CertIDSchema = v.pipe(
  v.string(),
  v.regex(certIDPattern),
);
