// revokeCert request payload (RFC 8555 §7.6)

import type { Base64url } from '../encoding';

/**
 * CRL reason codes usable in revokeCert (RFC 5280
 * §5.3.1).
 *
 * @remarks
 * Code `7` is reserved and MUST NOT appear in a CRL
 * — and therefore MUST NOT be submitted by a client.
 * Tuple order follows the RFC 5280 numeric order so
 * the human-readable label sits next to the numeric
 * code in reader's minds:
 *
 * - `0` — unspecified
 * - `1` — keyCompromise
 * - `2` — cACompromise
 * - `3` — affiliationChanged
 * - `4` — superseded
 * - `5` — cessationOfOperation
 * - `6` — certificateHold
 * - `8` — removeFromCRL
 * - `9` — privilegeWithdrawn
 * - `10` — aACompromise
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc5280#section-5.3.1}
 */
export const crlReasonCodes = [
  0, 1, 2, 3, 4, 5, 6, 8, 9, 10,
] as const;

/**
 * {@link crlReasonCodes} union.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc5280#section-5.3.1}
 */
export type CRLReasonCode = (typeof crlReasonCodes)[number];

/** Runtime set of valid CRL reason codes. */
export const CRLReasonCodes: ReadonlySet<CRLReasonCode> =
  new Set(crlReasonCodes);

/**
 * Certificate revocation payload.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.6}
 */
export type RevokeCert = {
  /** Base64url-encoded DER certificate. */
  certificate: Base64url
  /** CRL reason code (RFC 5280 §5.3.1). */
  reason?: CRLReasonCode
};
