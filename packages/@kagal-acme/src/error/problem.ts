// RFC 7807 Problem Document as a throwable error

import type { ErrorType } from '../types/constants/error-type';
import type { Identifier } from '../types/objects/identifier';
import {
  newProblem,
  newSubproblem,
  type Problem,
  type Subproblem,
} from '../types/objects/problem';

/**
 * Options for {@link ProblemError} factories.
 *
 * @remarks
 * Extends standard `ErrorOptions` with an optional
 * HTTP `status` override. Boulder occasionally reuses an
 * error URN with a non-default status — for instance,
 * `malformed` returned as 404 (resource not found) or 405
 * (method not allowed). Passing `status` lets a caller
 * keep the URN classification while overriding the
 * conventional value from {@link @kagal/acme/types#errorStatus}.
 *
 * Omit `status` to fall back to the table.
 */
export interface ProblemErrorOptions extends ErrorOptions {
  /**
   * Override the conventional HTTP status from
   * {@link @kagal/acme/types#errorStatus}.
   */
  status?: number
}

/**
 * Error that carries an RFC 7807 {@link @kagal/acme/types#Problem} document.
 *
 * @remarks
 * ACME failures are naturally expressed as Problem
 * Documents (RFC 7807 + RFC 8555 §6.7 extensions): a
 * `type` URN, an HTTP `status`, optional `detail` and
 * `title`, and an ACME-specific `subproblems` array
 * (each Subproblem may carry a per-identifier
 * context — RFC 8555 §6.7.1 forbids `identifier` at
 * the top level). Throwing `ProblemError` lets the
 * catching layer (typically an ACME server) surface the
 * document directly as the HTTP response body without a
 * second mapping step.
 *
 * The `message` is taken from `problem.detail`, then
 * `problem.title`, then `problem.type` — so
 * `console.error(err)` / stack traces remain readable.
 * The underlying cause (valibot issues, jose error,
 * `SyntaxError` from `JSON.parse`, etc.) is preserved
 * on `cause` via standard `Error` options.
 *
 * To emit the wire form (`application/problem+json`),
 * serialise the carried document directly —
 * `JSON.stringify(err.problem)` — not the `Error`
 * itself.
 *
 * Use {@link ProblemError.of} or one of the named
 * shortcuts ({@link ProblemError.malformed},
 * {@link ProblemError.unauthorized},
 * {@link ProblemError.serverInternal},
 * {@link ProblemError.compound}) to derive `status`
 * from the URN. Pass `options.status` to override the
 * conventional value (Boulder reuses `malformed` with
 * 404 / 405); reach for the constructor only when
 * shaping a Problem the factories don't cover.
 *
 * @example
 * ```typescript
 * try {
 *   // ...
 * } catch (cause) {
 *   throw ProblemError.malformed(
 *     'Flattened JWS failed schema validation',
 *     { cause },
 *   );
 * }
 * // at the HTTP boundary:
 * // response.body = JSON.stringify(err.problem);
 * ```
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7807}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-6.7}
 */
export class ProblemError extends Error {
  /** Problem Document describing the failure. */
  readonly problem: Problem;

  /**
   * Wrap a pre-built Problem document.
   *
   * @remarks
   * Use this path when shaping a Problem the static
   * factories don't cover — RFC 7807 `instance`, custom
   * `title`, extension fields, or a document
   * round-tripped from the wire. The document is held
   * **by reference** (no clone): the caller owns the
   * hermeticity of the object they pass.
   */
  constructor(problem: Problem, options?: ErrorOptions) {
    super(
      problem.detail ?? problem.title ?? problem.type,
      options,
    );
    this.name = 'ProblemError';
    this.problem = problem;
  }

  /**
   * Build a ProblemError from an ACME error URN,
   * deriving the conventional HTTP status from
   * {@link @kagal/acme/types#errorStatus} unless `options.status` overrides
   * it.
   */
  static of(
    type: ErrorType,
    detail?: string,
    options?: ProblemErrorOptions,
  ): ProblemError {
    const { status, ...errorOptions } = options ?? {};
    return new ProblemError(
      newProblem(type, detail, { status }),
      errorOptions,
    );
  }

  /** Malformed request (RFC 8555 §6.7 — default HTTP 400). */
  static malformed(
    detail?: string,
    options?: ProblemErrorOptions,
  ): ProblemError {
    return ProblemError.of(
      'urn:ietf:params:acme:error:malformed',
      detail,
      options,
    );
  }

  /**
   * JWS verification or account authorisation failure
   * (RFC 8555 §6.7 — default HTTP 403).
   */
  static unauthorized(
    detail?: string,
    options?: ProblemErrorOptions,
  ): ProblemError {
    return ProblemError.of(
      'urn:ietf:params:acme:error:unauthorized',
      detail,
      options,
    );
  }

  /**
   * Unhandled server-side failure
   * (RFC 8555 §6.7 — default HTTP 500).
   */
  static serverInternal(
    detail?: string,
    options?: ProblemErrorOptions,
  ): ProblemError {
    return ProblemError.of(
      'urn:ietf:params:acme:error:serverInternal',
      detail,
      options,
    );
  }

  /**
   * Aggregate sub-errors into a `compound` Problem
   * (RFC 8555 §6.7.1 — default HTTP 400).
   *
   * @remarks
   * Accepts plain {@link @kagal/acme/types#Subproblem} documents and
   * {@link SubproblemError} instances interchangeably —
   * the natural shape when each per-identifier validator
   * throws and a caller aggregates them via
   * `Promise.allSettled` or similar.
   * {@link SubproblemError.subproblem | `.subproblem`} is
   * unwrapped before serialisation; `Error.cause` on
   * the individual {@link SubproblemError} instances is
   * dropped, since `cause` lives on the `Error` wrapper —
   * not on the {@link @kagal/acme/types#Subproblem} document — and is not
   * part of the wire form.
   *
   * `subproblems` is deep-copied via `structuredClone`,
   * so post-throw mutation of the caller's array or any
   * contained Subproblem does not leak into the wire
   * form. The carried Problem's `subproblems` is the
   * canonical document for `JSON.stringify(err.problem)`.
   *
   * An empty `subproblems` array is structurally legal
   * but conveys nothing useful — the caller is expected
   * to guard with a `failures.length > 0` check before
   * throwing (see the `@example` on
   * {@link SubproblemError}).
   */
  static compound(
    subproblems: ReadonlyArray<Subproblem | SubproblemError>,
    detail?: string,
    options?: ProblemErrorOptions,
  ): ProblemError {
    const { status, ...errorOptions } = options ?? {};
    const documents = subproblems.map((entry) =>
      entry instanceof SubproblemError ? entry.subproblem : entry,
    );
    return new ProblemError(
      newProblem('urn:ietf:params:acme:error:compound', detail, {
        status,
        subproblems: structuredClone(documents),
      }),
      errorOptions,
    );
  }
};

/**
 * Error that carries an RFC 8555 §6.7.1 {@link @kagal/acme/types#Subproblem}.
 *
 * @remarks
 * A {@link @kagal/acme/types#Subproblem} describes a single per-identifier
 * failure that travels nested inside a `compound`
 * {@link @kagal/acme/types#Problem}. Throwing `SubproblemError` lets each
 * per-identifier validator fail independently — the
 * caller then aggregates a list of `SubproblemError`s
 * (typically via `Promise.allSettled`) and rolls them
 * into a `compound` via {@link ProblemError.compound},
 * which accepts both `Subproblem` and `SubproblemError`
 * entries.
 *
 * **Wire-boundary contract.** RFC 8555 §6.7.1 forbids
 * `identifier` at the top level of an ACME problem
 * document. A `SubproblemError` that escapes to the HTTP
 * boundary unwrapped would serialise with `identifier` at
 * the top level — a spec violation. Always funnel
 * `SubproblemError`s through {@link ProblemError.compound}
 * before the response is written; never surface a
 * `SubproblemError`'s `subproblem` directly as
 * `application/problem+json`.
 *
 * The `message` follows the same fallback chain as
 * {@link ProblemError}: `subproblem.detail`, then
 * `subproblem.title`, then `subproblem.type`. The
 * underlying cause is preserved on `cause` via standard
 * `Error` options.
 *
 * Use {@link SubproblemError.of} or one of the named
 * shortcuts ({@link SubproblemError.rejectedIdentifier},
 * {@link SubproblemError.caa}) to build a Subproblem from
 * its URN. Reach for the constructor only when shaping a
 * Subproblem the factories don't cover.
 *
 * @example
 * ```typescript
 * const results = await Promise.allSettled(
 *   identifiers.map(async (id) => {
 *     if (!await checkCAA(id)) {
 *       throw SubproblemError.caa(id, 'CAA forbids issuance');
 *     }
 *   }),
 * );
 * const failures = results
 *   .filter((r): r is PromiseRejectedResult => r.status === 'rejected')
 *   .map(r => r.reason)
 *   .filter((e): e is SubproblemError => e instanceof SubproblemError);
 * if (failures.length > 0) {
 *   throw ProblemError.compound(failures, 'Pre-issuance checks failed');
 * }
 * ```
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-6.7.1}
 */
export class SubproblemError extends Error {
  /** Subproblem describing the per-identifier failure. */
  readonly subproblem: Subproblem;

  /**
   * Wrap a pre-built Subproblem document.
   *
   * @remarks
   * Use this path when shaping a Subproblem the static
   * factories don't cover — `title`, RFC 7807 extension
   * fields, or a document round-tripped from the wire.
   * The document is held **by reference** (no clone): the
   * caller owns the hermeticity of the object they pass.
   */
  constructor(subproblem: Subproblem, options?: ErrorOptions) {
    super(
      subproblem.detail ?? subproblem.title ?? subproblem.type,
      options,
    );
    this.name = 'SubproblemError';
    this.subproblem = subproblem;
  }

  /**
   * Build a SubproblemError from an ACME error URN, with
   * an optional related identifier and detail.
   *
   * @remarks
   * `identifier` is optional per RFC 8555 §6.7.1 (a
   * Subproblem may describe a non-identifier-bound
   * failure aggregated into a compound). For URNs where
   * an identifier is conceptually required, prefer the
   * named shortcuts ({@link SubproblemError.rejectedIdentifier},
   * {@link SubproblemError.caa}).
   */
  static of(
    type: ErrorType,
    identifier?: Identifier,
    detail?: string,
    options?: ErrorOptions,
  ): SubproblemError {
    return new SubproblemError(
      newSubproblem(type, identifier, detail),
      options,
    );
  }

  /**
   * Build a `rejectedIdentifier` Subproblem (RFC 8555
   * §6.7) for the given identifier.
   */
  static rejectedIdentifier(
    identifier: Identifier,
    detail?: string,
    options?: ErrorOptions,
  ): SubproblemError {
    return SubproblemError.of(
      'urn:ietf:params:acme:error:rejectedIdentifier',
      identifier,
      detail,
      options,
    );
  }

  /**
   * Build a `caa` Subproblem (RFC 8555 §6.7) for the
   * given identifier.
   */
  static caa(
    identifier: Identifier,
    detail?: string,
    options?: ErrorOptions,
  ): SubproblemError {
    return SubproblemError.of(
      'urn:ietf:params:acme:error:caa',
      identifier,
      detail,
      options,
    );
  }
};
