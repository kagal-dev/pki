// ACME challenge type constants (RFC 8555 + RFC 8737)

/** Challenge type values. */
export const challengeTypes = [
  'dns-01',
  'http-01',
  'tls-alpn-01',
] as const;

/**
 * Challenge type union.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-8}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8737}
 */
export type ChallengeType = (typeof challengeTypes)[number];

/** Runtime set of valid challenge types. */
export const ChallengeTypes: ReadonlySet<ChallengeType> = new Set(challengeTypes);
