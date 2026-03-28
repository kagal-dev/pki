// Finalize request payload (RFC 8555 §7.4)

import type { Base64url } from '../encoding';

/**
 * Order finalisation payload.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.4}
 */
export type Finalize = {
  /** Base64url-encoded DER CSR. */
  csr: Base64url
};
