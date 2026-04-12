// ACME order (RFC 8555 §7.1.3)

import type { OrderStatus } from '../constants/status';
import type { Identifier } from './identifier';
import type { Problem } from './problem';
import type { CertID } from './renewal-info';

/**
 * ACME order object.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.3}
 */
export interface Order {
  /** Order state. */
  status: OrderStatus

  /** Authorization URLs. */
  authorizations: string[]
  /** Certificate download URL. */
  certificate?: string
  /** Error details. */
  error?: Problem
  /** RFC 3339 expiry timestamp. */
  expires?: string
  /** Finalize URL. */
  finalize: string
  /** Requested domains/IPs. */
  identifiers: Identifier[]

  /** Certificate validity end. */
  notAfter?: string
  /** Certificate validity start. */
  notBefore?: string

  /**
   * Selected profile (draft-ietf-acme-profiles).
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
