// Encoding validators

import * as v from 'valibot';

import {
  asBase64url,
  asBase64urlAlphabet,
  asPEM,
  type Base64url,
  type Base64urlAlphabet,
  type PEM,
} from '../types';

/** Base64url without padding (RFC 7515 §2). */
const base64url = /^[A-Za-z0-9_-]+$/;

/** Base64url allowing empty (POST-as-GET payload). */
const base64urlOrEmpty = /^[A-Za-z0-9_-]*$/;

/**
 * PEM armour — one or more `-----BEGIN <label>-----` /
 * `-----END <label>-----` blocks (RFC 7468 §3).
 *
 * @remarks
 * Structural check only — the label alphabet and the
 * payload contents are not validated here (that's
 * x509's job). Labels within a single block must
 * match (BEGIN vs END) via backreference; labels
 * across concatenated blocks may differ, so a mixed
 * certificate chain still validates.
 */
const pemArmour =
  /^(?:-----BEGIN ([^\n]+?)-----[\s\S]+?-----END \1-----\s*)+$/;

/**
 * Non-empty {@link Base64url} schema.
 *
 * @remarks
 * Output is branded — the trailing `v.transform` tags
 * the validated string as {@link Base64url} so
 * `InferOutput<typeof Base64urlSchema>` matches the
 * hand-written type exactly.
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
  v.transform((s): Base64url => asBase64url(s)),
);

/**
 * {@link Base64urlAlphabet} schema — non-empty string
 * using the base64url alphabet (RFC 4648 §5), without
 * the base64 byte-framing check.
 *
 * @remarks
 * Intended for RFC 8555 §8.1 challenge tokens — values
 * that "MUST NOT contain any characters outside the
 * base64url alphabet" but are not byte-encoded
 * payloads. A 25-character alphabet-only token passes
 * here but would fail {@link Base64urlSchema}'s
 * `length % 4 !== 1` check, so the two schemas brand
 * to distinct types.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc4648#section-5}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-8.1}
 */
export const Base64urlAlphabetSchema = v.pipe(
  v.string(),
  v.regex(base64url),
  v.transform((s): Base64urlAlphabet => asBase64urlAlphabet(s)),
);

/**
 * {@link Base64url} schema allowing empty string
 * (POST-as-GET payload, RFC 8555 §6.3).
 *
 * @remarks
 * Output is `'' | Base64url` — the empty case is
 * preserved as a literal empty string (the brand's
 * non-empty regex rejects `''`), while any non-empty
 * match is tagged as {@link Base64url}. This matches
 * the hand-written {@link FlattenedJWS.payload} type.
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
  v.transform((s): '' | Base64url =>
    s === '' ? '' : asBase64url(s),
  ),
);

/**
 * {@link PEM} armoured-text schema (RFC 7468).
 *
 * @remarks
 * Accepts one or more concatenated PEM blocks so a
 * single CSR/key/certificate and a full certificate
 * chain both validate. Within each block the BEGIN
 * and END labels must match (regex backreference);
 * the label alphabet and the base64 payload are
 * deferred to the downstream x509 parser. Output is
 * branded {@link PEM}.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7468}
 */
export const PEMSchema = v.pipe(
  v.string(),
  v.regex(pemArmour),
  v.transform((s): PEM => asPEM(s)),
);
