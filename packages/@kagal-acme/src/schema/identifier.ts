// Identifier schema (RFC 8555 §9.7.7, RFC 8738)

import * as v from 'valibot';

import { identifierTypes } from '../types/constants/identifier-type';

/** Shared identifier fields. */
const identifierFields = {
  type: v.picklist(identifierTypes),
  value: v.pipe(v.string(), v.minLength(1)),
};

/**
 * {@link Identifier} schema.
 *
 * @remarks
 * Uses `looseObject` — unknown fields pass through.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-9.7.7}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8738}
 */
export const IdentifierSchema = v.looseObject(
  identifierFields,
);

/**
 * Strict {@link Identifier} schema for request
 * payloads.
 *
 * @remarks
 * Uses `strictObject` — the client controls the
 * structure.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-9.7.7}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8738}
 */
export const StrictIdentifierSchema = v.strictObject(
  identifierFields,
);
