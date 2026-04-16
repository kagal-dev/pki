// ACME identifier (RFC 8555 §9.7.7, RFC 8738)

/**
 * DNS-name identifier (RFC 8555 §7.1.4).
 *
 * @remarks
 * `value` is a domain name in preferred-name form,
 * optionally prefixed by `*.` for wildcard orders.
 * Punycode-encoded IDN labels (`xn--…`) pass
 * naturally — structural validity only; registered-
 * name semantics are the CA's concern.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.4}
 */
export type DNSIdentifier = {
  type: 'dns'

  /** Domain name (optionally `*.`-prefixed wildcard). */
  value: string
};

/**
 * IP-address identifier (RFC 8738).
 *
 * @remarks
 * `value` is the textual form of the address — RFC
 * 1123 §2.1 dotted-decimal for IPv4, RFC 5952 §4
 * canonical text for IPv6.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8738}
 */
export type IPIdentifier = {
  type: 'ip'

  /** IPv4 or IPv6 textual form. */
  value: string
};

/**
 * Domain or IP identifier — discriminated on `type`.
 *
 * @remarks
 * Kept as a discriminated union so TypeScript can
 * narrow on `type` at the call site, and so the
 * Valibot schema can apply type-specific value
 * validation (DNS name regex vs IPv4/IPv6).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-9.7.7}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8738}
 */
export type Identifier = DNSIdentifier | IPIdentifier;
