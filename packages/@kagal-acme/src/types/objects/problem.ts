// RFC 7807 problem document with ACME extensions

import type { Identifier } from './identifier';

/**
 * Per-identifier sub-error (RFC 8555 §6.7.1).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-6.7.1}
 */
export interface Subproblem {
  /** URN error type. */
  type: string

  /** Human-readable description. */
  detail?: string
  /** Related identifier. */
  identifier?: Identifier
  /** URI reference for this occurrence (RFC 7807 §3.1). */
  instance?: string
  /** HTTP status code. */
  status?: number
  /** Human-readable summary (RFC 7807 §3.1). */
  title?: string
};

/**
 * ACME problem document (RFC 7807).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7807}
 */
export interface Problem extends Subproblem {
  /** Per-identifier errors. */
  subproblems?: Subproblem[]
};
