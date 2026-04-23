// ACME challenge types (RFC 8555 §7.1.5, RFC 8737)

import type { ChallengeStatus } from '../constants/status';
import type { Base64urlAlphabet } from '../encoding';

import type { Problem } from './problem';

/**
 * Shared challenge fields.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.5}
 */
export interface ChallengeBase {
  /** Error details. */
  error?: Problem
  /** Challenge state. */
  status: ChallengeStatus
  /**
   * Random token, base64url alphabet, ≥ 128 bits of
   * entropy (RFC 8555 §8.1). Branded
   * {@link Base64urlAlphabet} — alphabet-constrained
   * but not byte-framed, so never decoded.
   *
   * @remarks
   * RFC 8555 §8 classifies `token` as a per-type
   * field (defined in §8.3 for HTTP-01 and §8.4 for
   * DNS-01, plus §3 of RFC 8737 for TLS-ALPN-01),
   * not a basic challenge field. It lives in the
   * base here because every challenge type defined
   * to date carries it with identical semantics;
   * a future token-less challenge would split this
   * into a separate intermediate base.
   */
  token: Base64urlAlphabet
  /** Challenge URL. */
  url: string
  /** RFC 3339 validation timestamp. */
  validated?: string
};

/**
 * HTTP-01 challenge (RFC 8555 §8.3).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-8.3}
 */
export type HTTPChallenge = ChallengeBase & {
  type: 'http-01'
};

/**
 * DNS-01 challenge (RFC 8555 §8.4).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-8.4}
 */
export type DNSChallenge = ChallengeBase & {
  type: 'dns-01'
};

/**
 * TLS-ALPN-01 challenge (RFC 8737).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8737}
 */
export type TLSALPNChallenge = ChallengeBase & {
  type: 'tls-alpn-01'
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
