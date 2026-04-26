// RFC 7807 problem document with ACME extensions

import type { Identifier } from './identifier';

/**
 * Shared RFC 7807 problem-detail fields.
 *
 * @remarks
 * Common ground between {@link Problem} and
 * {@link Subproblem}. Per RFC 8555 §6.7.1 the two
 * shapes diverge — a top-level Problem MUST NOT carry
 * `identifier`, and a Subproblem cannot nest further
 * `subproblems` — so each adds exactly one extension on
 * top of this base.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7807#section-3.1}
 */
interface ProblemBase {
  /** URN error type. */
  type: string

  /** Human-readable description. */
  detail?: string
  /** URI reference for this occurrence (RFC 7807 §3.1). */
  instance?: string
  /** HTTP status code. */
  status?: number
  /** Human-readable summary (RFC 7807 §3.1). */
  title?: string
};

/**
 * Per-identifier sub-error (RFC 8555 §6.7.1).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-6.7.1}
 */
export interface Subproblem extends ProblemBase {
  /** Related identifier. */
  identifier?: Identifier
};

/**
 * ACME problem document (RFC 7807, RFC 8555 §6.7.1).
 *
 * @remarks
 * Does NOT extend {@link Subproblem}: per RFC 8555
 * §6.7.1, `identifier` MUST NOT appear at the top level
 * of an ACME problem document. Per-identifier failures
 * belong inside {@link subproblems} entries.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7807}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-6.7.1}
 */
export interface Problem extends ProblemBase {
  /** Per-identifier errors. */
  subproblems?: Subproblem[]
};
