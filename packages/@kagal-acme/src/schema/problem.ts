// Problem schema (RFC 7807, RFC 8555 §6.7.1)

import * as v from 'valibot';

import { IdentifierSchema } from './identifier';

/**
 * RFC 3986 URI-reference allowed character set —
 * unreserved, pct-encoded, sub-delims, and gen-delims.
 * Rejects whitespace and control characters (those
 * must be percent-encoded); doesn't parse scheme,
 * authority, or path structure. Matches the empty
 * string — non-empty is enforced by a separate
 * `v.nonEmpty()` action in the pipe so the intent is
 * visible next to the regex.
 */
const uriReference =
  /^[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=%]*$/;

/**
 * {@link Subproblem} schema.
 *
 * @remarks
 * Uses `looseObject` — unknown fields pass through.
 * `instance` is an RFC 7807 §3.1 URI-reference —
 * absolute URI or relative reference, per RFC 3986.
 * Validated structurally against the URI-reference
 * character set only; scheme / authority / path parse
 * is left to the consumer (or a `/utils` helper) when
 * it needs to dereference the value.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7807#section-3.1}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-6.7.1}
 */
export const SubproblemSchema = v.looseObject({
  type: v.string(),
  title: v.optional(v.string()),
  detail: v.optional(v.string()),
  status: v.optional(
    v.pipe(v.number(), v.integer(), v.minValue(100), v.maxValue(599)),
  ),
  instance: v.optional(
    v.pipe(v.string(), v.nonEmpty(), v.regex(uriReference)),
  ),
  identifier: v.optional(IdentifierSchema),
});

/**
 * {@link Problem} schema.
 *
 * @remarks
 * Uses `looseObject` — unknown fields pass through.
 * `type` is validated as a plain string, not against
 * {@link ErrorTypes}, to accept server-defined URNs
 * beyond the ACME namespace. `instance` is an RFC
 * 7807 §3.1 URI-reference — see {@link SubproblemSchema}
 * for the shared validation.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7807}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-6.7.1}
 */
export const ProblemSchema = v.looseObject({
  type: v.string(),
  title: v.optional(v.string()),
  detail: v.optional(v.string()),
  status: v.optional(
    v.pipe(v.number(), v.integer(), v.minValue(100), v.maxValue(599)),
  ),
  instance: v.optional(
    v.pipe(v.string(), v.nonEmpty(), v.regex(uriReference)),
  ),
  identifier: v.optional(IdentifierSchema),
  subproblems: v.optional(v.array(SubproblemSchema)),
});
