// ACME identifier (RFC 8555 §9.7.7, RFC 8738)

import type { IdentifierType } from '../constants/identifier-type';

/**
 * Domain or IP identifier.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-9.7.7}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8738}
 */
export interface Identifier {
  /** Identifier type — see {@link IdentifierType}. */
  type: IdentifierType
  /** Domain name or IP address. */
  value: string
};
