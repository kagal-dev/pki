// @kagal/acme/schema — Valibot validators for
// ACME protocol objects and request payloads
// (RFC 8555)

import * as v from 'valibot';

import type {
  Account,
  ACMEProtectedHeader,
  ACMERequestHeader,
  ACMESignAlgorithm,
  AuthorityInfoAccess,
  Authorization,
  Base64url,
  BasicConstraints,
  CertID,
  Challenge,
  CSR,
  DeactivateAccount,
  DeactivateAuthorization,
  Directory,
  DirectoryMeta,
  DistinguishedName,
  Extension,
  Finalize,
  FlattenedJWS,
  Identifier,
  JWK,
  JWSProtectedHeader,
  KeyChange,
  KeyUsage,
  NewAccount,
  NewAuthz,
  NewOrder,
  Order,
  PEM,
  Problem,
  RenewalInfo,
  RevokeCert,
  Subproblem,
} from '../types';

import { AccountSchema } from './account';
import { AuthorizationSchema } from './authorization';
import { ChallengeSchema } from './challenge';
import {
  AuthorityInfoAccessSchema,
  BasicConstraintsSchema,
  CSRSchema,
  DistinguishedNameSchema,
  ExtensionSchema,
  KeyUsageSchema,
} from './csr';
import {
  DirectoryMetaSchema,
  DirectorySchema,
} from './directory';
import {
  Base64urlOrEmptySchema,
  Base64urlSchema,
  PEMSchema,
} from './encoding';
import { FinalizeSchema } from './finalize';
import { IdentifierSchema } from './identifier';
import { JWKSchema } from './jwk';
import {
  ACMEProtectedHeaderSchema,
  ACMERequestHeaderSchema,
  ACMESignAlgorithmSchema,
  FlattenedJWSSchema,
  JWSProtectedHeaderSchema,
} from './jws';
import { KeyChangeSchema } from './key-change';
import {
  DeactivateAccountSchema,
  NewAccountSchema,
} from './new-account';
import {
  DeactivateAuthorizationSchema,
  NewAuthzSchema,
} from './new-authz';
import { NewOrderSchema } from './new-order';
import { OrderSchema } from './order';
import {
  ProblemSchema,
  SubproblemSchema,
} from './problem';
import {
  CertIDSchema,
  RenewalInfoSchema,
} from './renewal-info';
import { RevokeCertSchema } from './revoke-cert';

export { AccountSchema } from './account';
export { AuthorizationSchema } from './authorization';
export { ChallengeSchema } from './challenge';
export {
  AuthorityInfoAccessSchema,
  BasicConstraintsSchema,
  CSRSchema,
  DistinguishedNameSchema,
  ExtensionSchema,
  KeyUsageSchema,
} from './csr';
export {
  DirectoryMetaSchema,
  DirectorySchema,
} from './directory';
export {
  Base64urlOrEmptySchema,
  Base64urlSchema,
  PEMSchema,
} from './encoding';
export { FinalizeSchema } from './finalize';
export {
  IdentifierSchema,
  StrictIdentifierSchema,
} from './identifier';
export { JWKSchema } from './jwk';
export {
  ACMEProtectedHeaderSchema,
  ACMERequestHeaderSchema,
  ACMESignAlgorithmSchema,
  FlattenedJWSSchema,
  JWSProtectedHeaderSchema,
} from './jws';
export { KeyChangeSchema } from './key-change';
export {
  DeactivateAccountSchema,
  NewAccountSchema,
} from './new-account';
export {
  DeactivateAuthorizationSchema,
  NewAuthzSchema,
} from './new-authz';
export { NewOrderSchema } from './new-order';
export { OrderSchema } from './order';
export {
  ProblemSchema,
  SubproblemSchema,
} from './problem';
export {
  CertIDSchema,
  RenewalInfoSchema,
} from './renewal-info';
export { RevokeCertSchema } from './revoke-cert';

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
 * const result = validateOrder(json);
 * if (result.success) {
 *   result.data; // Order
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
 * Validate a {@link Base64url} string.
 *
 * @param input - raw string
 * @returns {@link ValidationResult} with
 *   {@link Base64url} on success
 */
export function validateBase64url(
  input: unknown,
): ValidationResult<Base64url> {
  return safeValidate(Base64urlSchema, input);
}

/**
 * Validate a {@link Base64url} string, allowing empty
 * (POST-as-GET payload).
 *
 * @param input - raw string
 * @returns {@link ValidationResult} with `'' | Base64url`
 *   on success — non-empty matches are branded; the
 *   empty case stays a literal empty string.
 */
export function validateBase64urlOrEmpty(
  input: unknown,
): ValidationResult<'' | Base64url> {
  return safeValidate(Base64urlOrEmptySchema, input);
}

/**
 * Validate {@link PEM} armoured text (RFC 7468).
 *
 * @param input - raw string
 * @returns {@link ValidationResult} with {@link PEM} on
 *   success. Accepts a single block or a concatenated
 *   chain; label contents and base64 payload are left
 *   to the x509 parser.
 */
export function validatePEM(
  input: unknown,
): ValidationResult<PEM> {
  return safeValidate(PEMSchema, input);
}

/**
 * Validate an {@link Account} payload.
 *
 * @param input - parsed JSON
 * @returns {@link ValidationResult} with
 *   {@link Account} on success
 */
export function validateAccount(
  input: unknown,
): ValidationResult<Account> {
  return safeValidate(AccountSchema, input);
}

/**
 * Validate an {@link AuthorityInfoAccess} shape.
 *
 * @remarks
 * Structural check only — verifies the optional
 * `ocsp` / `caIssuers` URL arrays. URL syntax is not
 * validated; the orchestrator owns policy on which
 * URL forms it will emit (RFC 5280 §4.2.2.1 admits
 * arbitrary URI forms).
 *
 * @param input - plain object
 * @returns {@link ValidationResult} with
 *   {@link AuthorityInfoAccess} on success
 */
export function validateAuthorityInfoAccess(
  input: unknown,
): ValidationResult<AuthorityInfoAccess> {
  return safeValidate(AuthorityInfoAccessSchema, input);
}

/**
 * Validate an {@link Authorization} payload.
 *
 * @param input - parsed JSON
 * @returns {@link ValidationResult} with
 *   {@link Authorization} on success
 */
export function validateAuthorization(
  input: unknown,
): ValidationResult<Authorization> {
  return safeValidate(AuthorizationSchema, input);
}

/**
 * Validate a {@link BasicConstraints} shape.
 *
 * @remarks
 * Structural check only — verifies the `ca` boolean
 * and the optional non-negative integer `pathLength`.
 * The signer enforces the RFC 5280 §4.2.1.9
 * "pathLength meaningful only when ca is true"
 * coupling at TBS encode time.
 *
 * @param input - plain object
 * @returns {@link ValidationResult} with
 *   {@link BasicConstraints} on success
 */
export function validateBasicConstraints(
  input: unknown,
): ValidationResult<BasicConstraints> {
  return safeValidate(BasicConstraintsSchema, input);
}

/**
 * Validate a {@link Challenge} payload.
 *
 * @param input - parsed JSON
 * @returns {@link ValidationResult} with
 *   {@link Challenge} on success
 */
export function validateChallenge(
  input: unknown,
): ValidationResult<Challenge> {
  return safeValidate(ChallengeSchema, input);
}

/**
 * Validate a {@link CertID} string.
 *
 * @param input - raw string
 * @returns {@link ValidationResult} with
 *   {@link CertID} on success
 */
export function validateCertID(
  input: unknown,
): ValidationResult<CertID> {
  return safeValidate(CertIDSchema, input);
}

/**
 * Validate a decoded {@link CSR} shape.
 *
 * @remarks
 * Structural check only — verifies the plain-object
 * form (subject, subjectPublicKey, sans, der).
 * Proof-of-possession is a crypto concern handled by
 * `parseCSR` in `@kagal/acme/utils`, not by this
 * validator.
 *
 * @param input - plain object
 * @returns {@link ValidationResult} with {@link CSR} on
 *   success
 */
export function validateCSR(
  input: unknown,
): ValidationResult<CSR> {
  return safeValidate(CSRSchema, input);
}

/**
 * Validate a {@link Directory} payload.
 *
 * @param input - parsed JSON
 * @returns {@link ValidationResult} with
 *   {@link Directory} on success
 */
export function validateDirectory(
  input: unknown,
): ValidationResult<Directory> {
  return safeValidate(DirectorySchema, input);
}

/**
 * Validate a {@link DirectoryMeta} payload.
 *
 * @param input - parsed JSON
 * @returns {@link ValidationResult} with
 *   {@link DirectoryMeta} on success
 */
export function validateDirectoryMeta(
  input: unknown,
): ValidationResult<DirectoryMeta> {
  return safeValidate(DirectoryMetaSchema, input);
}

/**
 * Validate a {@link DistinguishedName} shape.
 *
 * @remarks
 * Structural check only — verifies the outer
 * `Array<Record<string, string[]>>` form. Attribute
 * short-names (`CN`, `O`, `OU`, `C`, …) and their
 * value strings are not validated; that is the x509
 * encoder's concern.
 *
 * @param input - plain value
 * @returns {@link ValidationResult} with
 *   {@link DistinguishedName} on success
 */
export function validateDistinguishedName(
  input: unknown,
): ValidationResult<DistinguishedName> {
  return safeValidate(DistinguishedNameSchema, input);
}

/**
 * Validate a generic {@link Extension} envelope.
 *
 * @remarks
 * Structural check only — verifies the OID `id`,
 * optional `critical` boolean, and `value`
 * `Uint8Array`. The DER `value` is opaque to this
 * schema; downstream consumers (the signer's TBS
 * encoder, custom extension parsers) interpret it.
 *
 * @param input - plain object
 * @returns {@link ValidationResult} with
 *   {@link Extension} on success
 */
export function validateExtension(
  input: unknown,
): ValidationResult<Extension> {
  return safeValidate(ExtensionSchema, input);
}

/**
 * Validate a {@link Finalize} payload.
 *
 * @param input - parsed JSON
 * @returns {@link ValidationResult} with
 *   {@link Finalize} on success
 */
export function validateFinalize(
  input: unknown,
): ValidationResult<Finalize> {
  return safeValidate(FinalizeSchema, input);
}

/**
 * Validate a {@link FlattenedJWS} payload.
 *
 * @param input - parsed JSON
 * @returns {@link ValidationResult} with
 *   {@link FlattenedJWS} on success
 */
export function validateFlattenedJWS(
  input: unknown,
): ValidationResult<FlattenedJWS> {
  return safeValidate(FlattenedJWSSchema, input);
}

/**
 * Validate a {@link JWSProtectedHeader} payload.
 *
 * @param input - decoded protected header JSON
 * @returns {@link ValidationResult} with
 *   {@link JWSProtectedHeader} on success
 */
export function validateJWSProtectedHeader(
  input: unknown,
): ValidationResult<JWSProtectedHeader> {
  return safeValidate(
    JWSProtectedHeaderSchema, input,
  );
}

/**
 * Validate an {@link ACMEProtectedHeader} payload.
 *
 * @param input - decoded protected header JSON
 * @returns {@link ValidationResult} with
 *   {@link ACMEProtectedHeader} on success
 */
export function validateACMEProtectedHeader(
  input: unknown,
): ValidationResult<ACMEProtectedHeader> {
  return safeValidate(
    ACMEProtectedHeaderSchema, input,
  );
}

/**
 * Validate an {@link ACMERequestHeader} payload.
 *
 * @param input - decoded protected header JSON
 * @returns {@link ValidationResult} with
 *   {@link ACMERequestHeader} on success
 */
export function validateACMERequestHeader(
  input: unknown,
): ValidationResult<ACMERequestHeader> {
  return safeValidate(
    ACMERequestHeaderSchema, input,
  );
}

/**
 * Validate an {@link ACMESignAlgorithm} string.
 *
 * @param input - raw value (typically the `alg` field
 *   plucked from a decoded JWS protected header)
 * @returns {@link ValidationResult} with
 *   {@link ACMESignAlgorithm} on success
 *
 * @remarks
 * Standalone counterpart to the picklist composed by
 * {@link ACMEProtectedHeaderSchema} and
 * {@link ACMERequestHeaderSchema}. Use it to surface
 * an unsupported `alg` as RFC 8555 §6.7
 * `badSignatureAlgorithm` before the full header
 * schema runs and folds it into a generic
 * `malformed`.
 */
export function validateACMESignAlgorithm(
  input: unknown,
): ValidationResult<ACMESignAlgorithm> {
  return safeValidate(
    ACMESignAlgorithmSchema, input,
  );
}

/**
 * Validate an {@link Identifier} payload.
 *
 * @param input - parsed JSON
 * @returns {@link ValidationResult} with
 *   {@link Identifier} on success
 */
export function validateIdentifier(
  input: unknown,
): ValidationResult<Identifier> {
  return safeValidate(IdentifierSchema, input);
}

/**
 * Validate a {@link KeyUsage} bit name.
 *
 * @remarks
 * Single-name picklist check — rejects strings
 * outside the nine RFC 5280 §4.2.1.3 names. To
 * validate a full key-usage list, run the validator
 * over each entry; the schema layer keeps the
 * single-name check minimal so consumers can pick
 * their own collection shape.
 *
 * @param input - raw string
 * @returns {@link ValidationResult} with
 *   {@link KeyUsage} on success
 */
export function validateKeyUsage(
  input: unknown,
): ValidationResult<KeyUsage> {
  return safeValidate(KeyUsageSchema, input);
}

/**
 * Validate an {@link Order} payload.
 *
 * @param input - parsed JSON
 * @returns {@link ValidationResult} with
 *   {@link Order} on success
 */
export function validateOrder(
  input: unknown,
): ValidationResult<Order> {
  return safeValidate(OrderSchema, input);
}

/**
 * Validate a {@link Problem} payload.
 *
 * @param input - parsed JSON
 * @returns {@link ValidationResult} with
 *   {@link Problem} on success
 */
export function validateProblem(
  input: unknown,
): ValidationResult<Problem> {
  return safeValidate(ProblemSchema, input);
}

/**
 * Validate a {@link RenewalInfo} payload.
 *
 * @param input - parsed JSON
 * @returns {@link ValidationResult} with
 *   {@link RenewalInfo} on success
 */
export function validateRenewalInfo(
  input: unknown,
): ValidationResult<RenewalInfo> {
  return safeValidate(RenewalInfoSchema, input);
}

/**
 * Validate a {@link RevokeCert} payload.
 *
 * @param input - parsed JSON
 * @returns {@link ValidationResult} with
 *   {@link RevokeCert} on success
 */
export function validateRevokeCert(
  input: unknown,
): ValidationResult<RevokeCert> {
  return safeValidate(RevokeCertSchema, input);
}

/**
 * Validate a {@link Subproblem} payload.
 *
 * @param input - parsed JSON
 * @returns {@link ValidationResult} with
 *   {@link Subproblem} on success
 */
export function validateSubproblem(
  input: unknown,
): ValidationResult<Subproblem> {
  return safeValidate(SubproblemSchema, input);
}

/**
 * Validate a {@link JWK} payload.
 *
 * @param input - parsed JSON
 * @returns {@link ValidationResult} with
 *   {@link JWK} on success
 */
export function validateJWK(
  input: unknown,
): ValidationResult<JWK> {
  return safeValidate(JWKSchema, input);
}

/**
 * Validate a {@link KeyChange} payload.
 *
 * @param input - parsed JSON
 * @returns {@link ValidationResult} with
 *   {@link KeyChange} on success
 */
export function validateKeyChange(
  input: unknown,
): ValidationResult<KeyChange> {
  return safeValidate(KeyChangeSchema, input);
}

/**
 * Validate a {@link NewAccount} payload.
 *
 * @param input - parsed JSON
 * @returns {@link ValidationResult} with
 *   {@link NewAccount} on success
 */
export function validateNewAccount(
  input: unknown,
): ValidationResult<NewAccount> {
  return safeValidate(NewAccountSchema, input);
}

/**
 * Validate a {@link DeactivateAccount} payload.
 *
 * @param input - parsed JSON
 * @returns {@link ValidationResult} with
 *   {@link DeactivateAccount} on success
 */
export function validateDeactivateAccount(
  input: unknown,
): ValidationResult<DeactivateAccount> {
  return safeValidate(
    DeactivateAccountSchema, input,
  );
}

/**
 * Validate a {@link NewOrder} payload.
 *
 * @param input - parsed JSON
 * @returns {@link ValidationResult} with
 *   {@link NewOrder} on success
 */
export function validateNewOrder(
  input: unknown,
): ValidationResult<NewOrder> {
  return safeValidate(NewOrderSchema, input);
}

/**
 * Validate a {@link NewAuthz} payload.
 *
 * @param input - parsed JSON
 * @returns {@link ValidationResult} with
 *   {@link NewAuthz} on success
 */
export function validateNewAuthz(
  input: unknown,
): ValidationResult<NewAuthz> {
  return safeValidate(NewAuthzSchema, input);
}

/**
 * Validate a {@link DeactivateAuthorization}
 * payload.
 *
 * @param input - parsed JSON
 * @returns {@link ValidationResult} with
 *   {@link DeactivateAuthorization} on success
 */
export function validateDeactivateAuthorization(
  input: unknown,
): ValidationResult<DeactivateAuthorization> {
  return safeValidate(
    DeactivateAuthorizationSchema, input,
  );
}
