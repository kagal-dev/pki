// ACME identifier type constants (RFC 8555 + RFC 8738)

/** Identifier type values. */
export const identifierTypes = ['dns', 'ip'] as const;

/**
 * Identifier type union.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-9.7.7}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8738}
 */
export type IdentifierType = (typeof identifierTypes)[number];

/** Runtime set of valid identifier types. */
export const IdentifierTypes: ReadonlySet<IdentifierType> = new Set(identifierTypes);
