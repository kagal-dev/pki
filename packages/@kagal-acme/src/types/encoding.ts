// Encoding type aliases

// Nominal brands. String-keyed so `Base64url` / `PEM`
// are nameable across module boundaries — `unique
// symbol` brands trigger TS4023 when declaration emit
// carries the type through a second module (e.g. a
// schema output that transitively contains
// `Base64url`).

/**
 * Base64url-encoded string without padding
 * (RFC 7515 §2).
 *
 * @remarks
 * Branded `string`. Producers in `@kagal/acme/utils`
 * ({@link encodeBase64url}, {@link getRandom},
 * {@link jwkThumbprint}) return {@link Base64url}
 * directly, and {@link Base64urlSchema} outputs it
 * after validation — callers never assign from a
 * plain `string`. Use {@link asBase64url} to tag
 * already-trusted values (e.g. a row loaded from
 * storage that was validated at ingest).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7515#section-2}
 */
export type Base64url = string & {
  readonly _Base64urlBrand: void
};

/**
 * Tag `value` as {@link Base64url} without runtime
 * validation. Use at trust boundaries — right after a
 * known-correct encoder (`btoa` + substitution), or
 * when loading a row that was validated at ingest.
 * Untrusted input must go through
 * {@link validateBase64url} from `@kagal/acme/schema`
 * instead.
 *
 * @example
 * ```typescript
 * const nonce = asBase64url(row.nonce);
 * ```
 */
export function asBase64url(value: string): Base64url {
  return value as Base64url;
}

/**
 * String constrained to the base64url alphabet
 * (RFC 4648 §5) without byte-framing.
 *
 * @remarks
 * RFC 8555 §8.1 describes challenge tokens as values
 * that "MUST NOT contain any characters outside the
 * base64url alphabet", with no requirement that the
 * length be a valid base64 framing — a 25-character
 * alphabet-only token is conformant. Distinct from
 * {@link Base64url}, which brands byte-framed,
 * decodable values.
 *
 * Branded `string`. Use for values that are compared
 * as opaque strings rather than decoded: challenge
 * tokens, similar random identifiers. Consumers that
 * decode (via `decodeBase64url`) must demand
 * {@link Base64url} instead.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc4648#section-5}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-8.1}
 */
export type Base64urlAlphabet = string & {
  readonly _Base64urlAlphabetBrand: void
};

/**
 * Tag `value` as {@link Base64urlAlphabet} without
 * runtime validation. Use at trust boundaries — after
 * a known-correct producer or a row validated at
 * ingest. Untrusted input goes through the schema
 * layer.
 *
 * @example
 * ```typescript
 * const token = asBase64urlAlphabet(row.token);
 * ```
 */
export function asBase64urlAlphabet(value: string): Base64urlAlphabet {
  return value as Base64urlAlphabet;
}

// cspell:words serialiser serialisers
/**
 * PEM-encoded text with `-----BEGIN`/`-----END` armour
 * (RFC 7468). Used for keys, CSRs, certificates, and
 * concatenated certificate chains.
 *
 * @remarks
 * Branded `string`. Producers (x509 serialisers,
 * storage readers) return {@link PEM} directly; use
 * {@link asPEM} to tag already-trusted armoured text.
 * Always means PEM with armour — never base64, never
 * DER.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7468}
 */
export type PEM = string & {
  readonly _PEMBrand: void
};

/**
 * Tag `value` as {@link PEM} without runtime
 * validation. Use at trust boundaries — when the
 * armoured text comes from a known-correct producer
 * (e.g. `@peculiar/x509` serialisers) or a store
 * where the armour was checked at ingest.
 *
 * @example
 * ```typescript
 * const cert = asPEM(serialiser.toString());
 * ```
 */
export function asPEM(value: string): PEM {
  return value as PEM;
}
