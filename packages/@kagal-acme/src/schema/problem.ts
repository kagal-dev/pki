// Problem schema (RFC 7807, RFC 8555 §6.7.1)

import * as v from 'valibot';

import { IdentifierSchema } from './identifier';

/**
 * {@link Subproblem} schema.
 *
 * @remarks
 * Uses `looseObject` — unknown fields pass through.
 * `instance` is tightened to an absolute URL — RFC
 * 7807 §3.1 permits relative URI references, but
 * ACME CAs serve absolute URLs in practice and the
 * strict form catches malformed wire. Relax if a
 * real CA emits relative refs.
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
  instance: v.optional(v.pipe(v.string(), v.url())),
  identifier: v.optional(IdentifierSchema),
});

/**
 * {@link Problem} schema.
 *
 * @remarks
 * Uses `looseObject` — unknown fields pass through.
 * `type` is validated as a plain string, not against
 * {@link ErrorTypes}, to accept server-defined URNs
 * beyond the ACME namespace. `instance` is an
 * absolute URL — see {@link SubproblemSchema} for
 * the rationale.
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
  instance: v.optional(v.pipe(v.string(), v.url())),
  identifier: v.optional(IdentifierSchema),
  subproblems: v.optional(v.array(SubproblemSchema)),
});
