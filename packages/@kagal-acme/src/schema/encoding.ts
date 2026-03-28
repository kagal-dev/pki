// Encoding validators

import * as v from 'valibot';

/** Base64url without padding (RFC 7515 §2). */
const base64url = /^[A-Za-z0-9_-]+$/;

/** Base64url allowing empty (POST-as-GET payload). */
const base64urlOrEmpty = /^[A-Za-z0-9_-]*$/;

/**
 * Non-empty {@link Base64url} schema.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7515#section-2}
 */
export const Base64urlSchema = v.pipe(
  v.string(),
  v.regex(base64url),
  v.check(
    (s) => s.length % 4 !== 1,
    'invalid base64url length',
  ),
);

/**
 * {@link Base64url} schema allowing empty string
 * (POST-as-GET payload, RFC 8555 §6.3).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-6.3}
 */
export const Base64urlOrEmptySchema = v.pipe(
  v.string(),
  v.regex(base64urlOrEmpty),
  v.check(
    (s) => s === '' || s.length % 4 !== 1,
    'invalid base64url length',
  ),
);
