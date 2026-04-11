// Problem schema (RFC 7807, RFC 8555 §6.7.1)

import * as v from 'valibot';

import { IdentifierSchema } from './identifier';

/**
 * {@link Subproblem} schema.
 *
 * @remarks
 * Uses `looseObject` — unknown fields pass through.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-6.7.1}
 */
export const SubproblemSchema = v.looseObject({
  type: v.string(),
  title: v.optional(v.string()),
  detail: v.optional(v.string()),
  status: v.optional(
    v.pipe(v.number(), v.integer(), v.minValue(100), v.maxValue(599)),
  ),
  instance: v.optional(v.string()),
  identifier: v.optional(IdentifierSchema),
});

/**
 * {@link Problem} schema.
 *
 * @remarks
 * Uses `looseObject` — unknown fields pass through.
 * `type` is validated as a plain string, not against
 * {@link ErrorTypes}, to accept server-defined URNs
 * beyond the ACME namespace.
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
  instance: v.optional(v.string()),
  identifier: v.optional(IdentifierSchema),
  subproblems: v.optional(v.array(SubproblemSchema)),
});
