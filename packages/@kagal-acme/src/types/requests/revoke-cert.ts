// revokeCert request payload (RFC 8555 §7.6)

import type { Base64url } from '../encoding';

/**
 * CRL reason code (RFC 5280 §5.3.1).
 *
 * @remarks
 * Code 7 is not used.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc5280#section-5.3.1}
 */
export type CRLReasonCode =
  0 | // unspecified
  1 | // keyCompromise
  2 | // cACompromise
  3 | // affiliationChanged
  4 | // superseded
  5 | // cessationOfOperation
  6 | // certificateHold
  8 | // removeFromCRL
  9 | // privilegeWithdrawn
  10; // aACompromise

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
