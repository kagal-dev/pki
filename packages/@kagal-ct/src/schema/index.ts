// @kagal/ct/schema — Valibot validators for
// Certificate Transparency objects (RFC 9162)

import * as v from 'valibot';

import type { Base64 } from '../types/encoding';

import type {
  ConsistencyProof,
  InclusionProof,
  LogEntry,
  SignedCertificateTimestamp,
  SignedTreeHead,
  SubmittedEntry,
} from '../types/ct';

import { Base64Schema } from './encoding';

import {
  ConsistencyProofSchema,
  InclusionProofSchema,
  LogEntrySchema,
  SignedCertificateTimestampSchema,
  SignedTreeHeadSchema,
  SubmittedEntrySchema,
} from './ct';

export { Base64Schema } from './encoding';

export {
  ConsistencyProofSchema,
  InclusionProofSchema,
  LogEntrySchema,
  SignedCertificateTimestampSchema,
  SignedTreeHeadSchema,
  SubmittedEntrySchema,
} from './ct';

/**
 * Successful validation — discriminate on `success`.
 *
 * @typeParam T - the validated type
 */
export type ValidationSuccess<T> = {
  success: true

  data: T
};

/**
 * Failed validation — discriminate on `success`.
 *
 * @remarks
 * `issues` contains Valibot's structured error
 * details (path, message, expected/received).
 */
export type ValidationFailure = {
  success: false

  issues: v.BaseIssue<unknown>[]
};

/**
 * Discriminated validation result.
 *
 * @typeParam T - the validated type on success
 *
 * @example
 * ```typescript
 * const result = validateSignedTreeHead(json);
 * if (result.success) {
 *   result.data; // SignedTreeHead
 * } else {
 *   result.issues; // BaseIssue<unknown>[]
 * }
 * ```
 */
export type ValidationResult<T> =
  ValidationFailure |
  ValidationSuccess<T>;

function safeValidate<
  TSchema extends v.BaseSchema<
    unknown, unknown, v.BaseIssue<unknown>
  >,
  T,
>(
  schema: TSchema,
  input: unknown,
): ValidationResult<T> {
  const result = v.safeParse(schema, input);
  // Safe: conformance.types.ts asserts InferOutput ≡ T
  return result.success ?
    { success: true, data: result.output as T } :
    { success: false, issues: result.issues };
}

/**
 * Validate a {@link Base64} string.
 *
 * @param input - raw string
 * @returns {@link ValidationResult} with
 *   {@link Base64} on success
 */
export function validateBase64(
  input: unknown,
): ValidationResult<Base64> {
  return safeValidate(Base64Schema, input);
}

/**
 * Validate a {@link SignedTreeHead} payload.
 *
 * @param input - parsed JSON
 * @returns {@link ValidationResult} with
 *   {@link SignedTreeHead} on success
 */
export function validateSignedTreeHead(
  input: unknown,
): ValidationResult<SignedTreeHead> {
  return safeValidate(SignedTreeHeadSchema, input);
}

/**
 * Validate a {@link SignedCertificateTimestamp}
 * payload.
 *
 * @param input - parsed JSON
 * @returns {@link ValidationResult} with
 *   {@link SignedCertificateTimestamp} on success
 */
export function validateSignedCertificateTimestamp(
  input: unknown,
): ValidationResult<SignedCertificateTimestamp> {
  return safeValidate(
    SignedCertificateTimestampSchema, input,
  );
}

/**
 * Validate a {@link SubmittedEntry} payload.
 *
 * @param input - parsed JSON
 * @returns {@link ValidationResult} with
 *   {@link SubmittedEntry} on success
 */
export function validateSubmittedEntry(
  input: unknown,
): ValidationResult<SubmittedEntry> {
  return safeValidate(SubmittedEntrySchema, input);
}

/**
 * Validate a {@link LogEntry} payload.
 *
 * @param input - parsed JSON
 * @returns {@link ValidationResult} with
 *   {@link LogEntry} on success
 */
export function validateLogEntry(
  input: unknown,
): ValidationResult<LogEntry> {
  return safeValidate(LogEntrySchema, input);
}

/**
 * Validate an {@link InclusionProof} payload.
 *
 * @param input - parsed JSON
 * @returns {@link ValidationResult} with
 *   {@link InclusionProof} on success
 */
export function validateInclusionProof(
  input: unknown,
): ValidationResult<InclusionProof> {
  return safeValidate(InclusionProofSchema, input);
}

/**
 * Validate a {@link ConsistencyProof} payload.
 *
 * @param input - parsed JSON
 * @returns {@link ValidationResult} with
 *   {@link ConsistencyProof} on success
 */
export function validateConsistencyProof(
  input: unknown,
): ValidationResult<ConsistencyProof> {
  return safeValidate(
    ConsistencyProofSchema, input,
  );
}
