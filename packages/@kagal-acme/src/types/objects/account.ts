// ACME account (RFC 8555 §7.1.2)

import type { AccountStatus } from '../constants/status';
import type { FlattenedJWS } from '../jws/jws';

/**
 * External account binding (RFC 8555 §7.3.4).
 *
 * Structurally identical to {@link FlattenedJWS} —
 * the payload is the account's public key, signed
 * with the EAB HMAC key.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.4}
 */
export type ExternalAccountBinding = FlattenedJWS;

/**
 * ACME account object.
 *
 * @remarks
 * RFC 8555 §7.1.2 lists `orders` as required, but
 * Boulder/Let's Encrypt omit it in account responses.
 * The field is modelled as optional for interoperability.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.2}
 */
export interface Account {
  /** Account state. */
  status: AccountStatus

  /** Contact URIs (`mailto:...`). */
  contact?: string[]
  /** EAB JWS (registration only). */
  externalAccountBinding?: ExternalAccountBinding
  /** URL to order list. */
  orders?: string
  /** Whether ToS was accepted. */
  termsOfServiceAgreed?: boolean
};
