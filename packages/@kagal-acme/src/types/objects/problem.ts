// RFC 7807 problem document — ACME types and data factories

import type { Identifier } from './identifier';
import { errorStatus, type ErrorType } from '../constants';

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

/**
 * Options for {@link newProblem}.
 *
 * @remarks
 * `status` overrides the conventional HTTP status from
 * {@link errorStatus} — Boulder reuses some URNs (e.g.
 * `malformed`) with non-default statuses (404, 405).
 * `subproblems` attaches per-identifier sub-errors;
 * RFC 8555 §6.7.1 permits any top-level URN to carry
 * subproblems (the §6.7.1 worked example uses
 * `malformed` rather than `compound`).
 */
export interface NewProblemOptions {
  /**
   * Override the conventional HTTP status from
   * {@link errorStatus}.
   */
  status?: number

  /**
   * Per-identifier sub-errors attached to the document.
   * Referenced by reference — the caller owns
   * hermeticity (clone before passing if isolation
   * matters).
   */
  subproblems?: Subproblem[]
};

/**
 * Build a {@link Problem} document from an ACME error
 * URN.
 *
 * @remarks
 * Pure data factory — returns a plain object suitable
 * for the `application/problem+json` wire form. Use
 * this where the call site's contract is to return a
 * `Problem` rather than throw — for example a deps
 * callback that signals "rejected" via a returned
 * Problem document.
 *
 * Always emits `status` — derived from
 * {@link errorStatus} by URN unless `options.status`
 * overrides it. Callers wanting `status` omitted from
 * the serialised form must `delete problem.status`
 * (uncommon; the typical wire pattern includes it).
 * Pass `options.subproblems` to attach per-identifier
 * sub-errors (any top-level URN is permitted by RFC 8555
 * §6.7.1; `compound` is the canonical aggregator). The
 * array is held by reference — clone before passing if
 * isolation from later mutation matters.
 *
 * RFC 7807 §3.1 also defines `title` and `instance`. In
 * the dominant ACME usage these are unused, so this
 * factory surfaces only `type`, `status`, `detail`, and
 * `subproblems` — construct a Problem literal directly
 * if a call site needs the rarer fields.
 *
 * @example
 * ```typescript
 * // Reject from a deps callback that returns Problem | undefined.
 * return newProblem(
 *   'urn:ietf:params:acme:error:rejectedIdentifier',
 *   'Identifier outside allowed set',
 * );
 * ```
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7807}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-6.7}
 */
export function newProblem(
  type: ErrorType,
  detail?: string,
  options?: NewProblemOptions,
): Problem {
  const { status, subproblems } = options ?? {};
  return {
    type,
    status: status ?? errorStatus[type],
    ...(detail !== undefined && { detail }),
    ...(subproblems !== undefined && { subproblems }),
  };
}

/**
 * Build a {@link Subproblem} document from an ACME error
 * URN.
 *
 * @remarks
 * Pure data factory — returns a plain object suitable
 * for nesting inside {@link Problem.subproblems}. RFC
 * 8555 §6.7.1 permits an `identifier` field on
 * subproblems but forbids it at the top level of a
 * Problem; the type system reflects this — `Subproblem`
 * carries `identifier?` while `Problem` does not.
 *
 * RFC 8555 §6.7.1 specifies that subproblems share the
 * fields of a Problem document, so a Subproblem may
 * structurally carry `status`, `title`, or `instance`.
 * In the dominant ACME usage the parent Problem's
 * `status` describes the HTTP response, so this factory
 * surfaces only `type`, `identifier`, and `detail` —
 * construct a Subproblem literal directly if a call site
 * needs the rarer fields. Pass the result to
 * {@link newProblem}'s `subproblems` option.
 *
 * The parameter shape is positional —
 * `(type, identifier?, detail?)` rather than
 * `(type, detail?, options?)` of {@link newProblem}.
 * `identifier` is the primary discriminator on a
 * sub-error, not an optional adjunct, so it stays in
 * the argument list.
 *
 * @example
 * ```typescript
 * const sub = newSubproblem(
 *   'urn:ietf:params:acme:error:caa',
 *   { type: 'dns', value: 'forbidden.example' },
 *   'CAA forbids issuance',
 * );
 * return newProblem(
 *   'urn:ietf:params:acme:error:compound',
 *   'Pre-issuance checks failed',
 *   { subproblems: [sub] },
 * );
 * ```
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-6.7.1}
 */
export function newSubproblem(
  type: ErrorType,
  identifier?: Identifier,
  detail?: string,
): Subproblem {
  return {
    type,
    ...(identifier !== undefined && { identifier }),
    ...(detail !== undefined && { detail }),
  };
}
