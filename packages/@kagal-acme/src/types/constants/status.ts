// ACME object status constants (RFC 8555)

/** Order status values (RFC 8555 §7.1.3). */
export const orderStatuses = [
  'pending',
  'ready',
  'processing',
  'valid',
  'invalid',
] as const;

/**
 * Order status union type.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.3}
 */
export type OrderStatus = (typeof orderStatuses)[number];

/** Runtime set of valid order statuses. */
export const OrderStatuses: ReadonlySet<OrderStatus> = new Set(orderStatuses);

/** Authorization status values (RFC 8555 §7.1.4). */
export const authorizationStatuses = [
  'pending',
  'valid',
  'invalid',
  'deactivated',
  'expired',
  'revoked',
] as const;

/**
 * Authorisation status union type.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.4}
 */
export type AuthorizationStatus = (typeof authorizationStatuses)[number];

/** Runtime set of valid authorisation statuses. */
export const AuthorizationStatuses: ReadonlySet<AuthorizationStatus> = new Set(authorizationStatuses);

/** Challenge status values (RFC 8555 §7.1.5). */
export const challengeStatuses = [
  'pending',
  'processing',
  'valid',
  'invalid',
] as const;

/**
 * Challenge status union type.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.5}
 */
export type ChallengeStatus = (typeof challengeStatuses)[number];

/** Runtime set of valid challenge statuses. */
export const ChallengeStatuses: ReadonlySet<ChallengeStatus> = new Set(challengeStatuses);

/** Account status values (RFC 8555 §7.1.2). */
export const accountStatuses = [
  'valid',
  'deactivated',
  'revoked',
] as const;

/**
 * Account status union type.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.2}
 */
export type AccountStatus = (typeof accountStatuses)[number];

/** Runtime set of valid account statuses. */
export const AccountStatuses: ReadonlySet<AccountStatus> = new Set(accountStatuses);
