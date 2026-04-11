// newOrder request payload (RFC 8555 §7.4)

import type { Identifier } from '../objects/identifier';
import type { CertID } from '../objects/renewal-info';

/**
 * newOrder request payload.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.4}
 */
export type NewOrder = {
  /** Requested identifiers. */
  identifiers: Identifier[]
  /** Certificate validity start (RFC 3339). */
  notBefore?: string
  /** Certificate validity end (RFC 3339). */
  notAfter?: string
  /**
   * Desired profile name.
   *
   * @beta
   * @see {@link https://datatracker.ietf.org/doc/draft-ietf-acme-profiles/}
   */
  profile?: string
  /**
   * ARI predecessor certID (RFC 9773 §5).
   *
   * @see {@link https://datatracker.ietf.org/doc/html/rfc9773#section-5}
   */
  replaces?: CertID
};
