// Encoding validators

import * as v from 'valibot';

/** Standard base64 with optional padding (RFC 4648 §4). */
const base64 = /^[A-Za-z0-9+/]+={0,2}$/;

/**
 * Non-empty {@link Base64} schema.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc4648#section-4}
 */
export const Base64Schema = v.pipe(
  v.string(),
  v.regex(base64),
  v.check(
    (s) => {
      if (s.endsWith('=')) {
        return s.length % 4 === 0;
      }
      return s.length % 4 !== 1;
    },
    'invalid base64 length',
  ),
);
