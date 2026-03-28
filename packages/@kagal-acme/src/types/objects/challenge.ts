// ACME challenge types (RFC 8555 §7.1.5, RFC 8737)

import type { ChallengeStatus } from '../constants/status';
import type { Problem } from './problem';

/**
 * Shared challenge fields.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.5}
 */
export interface ChallengeBase {
  /** Challenge URL. */
  url: string
  /** Challenge state. */
  status: ChallengeStatus
  /** RFC 3339 validation timestamp. */
  validated?: string
  /** Error details. */
  error?: Problem
};

/**
 * HTTP-01 challenge (RFC 8555 §8.3).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-8.3}
 */
export type HTTPChallenge = ChallengeBase & {
  type: 'http-01'
  token: string
};

/**
 * DNS-01 challenge (RFC 8555 §8.4).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-8.4}
 */
export type DNSChallenge = ChallengeBase & {
  type: 'dns-01'
  token: string
};

/**
 * TLS-ALPN-01 challenge (RFC 8737).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8737}
 */
export type TLSALPNChallenge = ChallengeBase & {
  type: 'tls-alpn-01'
  token: string
};

/**
 * Discriminated challenge union.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-8}
 */
export type Challenge =
  DNSChallenge |
  HTTPChallenge |
  TLSALPNChallenge;
