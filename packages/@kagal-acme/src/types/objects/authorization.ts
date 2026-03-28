// ACME authorization (RFC 8555 §7.1.4)

import type { AuthorizationStatus } from '../constants/status';
import type { Challenge } from './challenge';
import type { Identifier } from './identifier';

/**
 * Shared authorisation fields.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.4}
 */
export interface AuthorizationBase {
  /** Subject identifier. */
  identifier: Identifier
  /** Associated challenges. */
  challenges: Challenge[]
  /** RFC 3339 expiry timestamp. */
  expires?: string
  /** True for wildcard authorisations. */
  wildcard?: boolean
};

/**
 * Discriminated authorisation union.
 *
 * @remarks
 * `expires` is required when status is `'valid'`.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.4}
 */
export type Authorization =
  AuthorizationBase & {
    status: 'pending'
  } |
  AuthorizationBase & {
    status: 'valid'
    /** Required when valid. */
    expires: string
  } |
  AuthorizationBase & {
    status: Exclude<AuthorizationStatus, 'pending' | 'valid'>
  };
