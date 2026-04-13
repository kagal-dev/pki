// newAccount request payload (RFC 8555 §7.3)

import type {
  ExternalAccountBinding,
} from '../objects/account';

/**
 * newAccount request payload.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.3}
 */
export type NewAccount = {
  /** Contact URIs. */
  contact?: string[]
  /** External account binding JWS. */
  externalAccountBinding?: ExternalAccountBinding
  /** Return existing account only. */
  onlyReturnExisting?: boolean
  /** ToS agreement. */
  termsOfServiceAgreed?: boolean
};

/**
 * Account deactivation payload.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.6}
 */
export type DeactivateAccount = {
  status: 'deactivated'
};
