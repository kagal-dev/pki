// keyChange inner payload (RFC 8555 §7.3.5)

import type { JWK } from '../jws/jwk';

/**
 * Inner JWS payload for key rollover.
 *
 * @remarks
 * Signed with the new key; the outer JWS is signed
 * with the old key.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.5}
 */
export type KeyChange = {
  /** Account URL. */
  account: string
  /** Old account public key. */
  oldKey: JWK
};
