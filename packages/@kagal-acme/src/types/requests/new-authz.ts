// newAuthz request payload (RFC 8555 §7.4.1)

import type { Identifier } from '../objects/identifier';

/**
 * Pre-authorisation request payload.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.4.1}
 */
export type NewAuthz = {
  /** Identifier to pre-authorise. */
  identifier: Identifier
};

/**
 * Authorisation deactivation payload.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.5.2}
 */
export type DeactivateAuthorization = {
  status: 'deactivated'
};
