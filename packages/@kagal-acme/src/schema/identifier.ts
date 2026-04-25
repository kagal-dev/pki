// Identifier schema (RFC 8555 §9.7.7, RFC 8738)

import * as v from 'valibot';

/**
 * Domain name or wildcard identifier.
 *
 * @remarks
 * Structural LDH check — labels are alphanumeric
 * with optional internal hyphens (no leading or
 * trailing `-`), dot-separated, optionally prefixed
 * by `*.` for wildcard orders. Punycode-encoded IDN
 * labels (`xn--…`) pass naturally. Label length,
 * total length, public-suffix rules, and registered-
 * name semantics are left to the CA.
 */
const dnsLabel = '[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?';
const dnsName = new RegExp(
  String.raw`^(?:\*\.)?${dnsLabel}(?:\.${dnsLabel})*$`,
);

/**
 * `type: 'dns'` value schema — DNS name (optional
 * `*.`).
 *
 * @remarks
 * A `check` requires at least one letter somewhere
 * in the name — otherwise an IPv4 address like
 * `192.0.2.1` would pass the LDH regex (digits and
 * dots are both valid) and a payload tagged as
 * `dns` with a numeric-only value would validate.
 * RFC 8738 mandates `type: 'ip'` for IPs; catching
 * the ambiguity here prevents a silent mis-type
 * upstream.
 */
const dnsValue = v.pipe(
  v.string(),
  v.regex(dnsName),
  v.check(
    (s) => /[a-zA-Z]/.test(s),
    'domain name must contain at least one letter',
  ),
);

// cspell:words hextets
/**
 * `type: 'ip'` value schema — IPv4 dotted or IPv6
 * textual form.
 *
 * @remarks
 * Accepts any RFC 4291 textual IPv6 form: uppercase
 * hex digits, leading zeros in hextets, and
 * non-optimal `::` placement all validate. RFC 5952
 * canonical form is deliberately not enforced here —
 * the schema layer rejects obviously bad wire data,
 * and canonicalisation lives one layer up in `/utils`
 * (via `ipaddr.js` or similar) when a consumer needs
 * it before storage or issuance.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc4291}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc5952}
 */
const ipValue = v.union([
  v.pipe(v.string(), v.ipv4()),
  v.pipe(v.string(), v.ipv6()),
]);

/**
 * {@link Identifier} schema — discriminated on `type`.
 *
 * @remarks
 * Uses `v.variant` so each identifier type carries
 * its own value validation: DNS preferred-name /
 * wildcard form for `'dns'`, and IPv4 or IPv6
 * textual form for `'ip'`. Each branch is a
 * `looseObject` — unknown fields on the wire pass
 * through.
 *
 * Adding a new identifier type (RFC 8823 email, a
 * future RFC, etc.) requires a new branch here with
 * its own value validator — there's no shared
 * "any string" fallback, on purpose: a value that
 * means something for DNS is probably garbage for
 * IP.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-9.7.7}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8738}
 */
export const IdentifierSchema = v.variant('type', [
  v.looseObject({
    type: v.literal('dns'),
    value: dnsValue,
  }),
  v.looseObject({
    type: v.literal('ip'),
    value: ipValue,
  }),
]);

/**
 * Strict {@link Identifier} schema for request
 * payloads.
 *
 * @remarks
 * Uses `strictObject` — the client controls the
 * structure, so unknown fields are an error rather
 * than a forward-compat extension.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-9.7.7}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8738}
 */
export const StrictIdentifierSchema = v.variant('type', [
  v.strictObject({
    type: v.literal('dns'),
    value: dnsValue,
  }),
  v.strictObject({
    type: v.literal('ip'),
    value: ipValue,
  }),
]);
