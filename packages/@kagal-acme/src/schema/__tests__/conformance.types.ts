// Schema ↔ type conformance — compile-time assertions.
// If schema and hand-written type drift, tsc fails.

import { expectTypeOf } from 'vitest';

import type { SchemaOutput } from './test-utils';

import type {
  Account,
  ACMEProtectedHeader,
  ACMERequestHeader,
  ACMESignAlgorithm,
  Authorization,
  CertID,
  Challenge,
  DeactivateAccount,
  DeactivateAuthorization,
  Directory,
  DirectoryMeta,
  Finalize,
  FlattenedJWS,
  Identifier,
  JWK,
  JWSProtectedHeader,
  KeyChange,
  NewAccount,
  NewAuthz,
  NewOrder,
  Order,
  Problem,
  RenewalInfo,
  RevokeCert,
  Subproblem,
} from '../../types';

import type {
  AccountSchema,
  ACMEProtectedHeaderSchema,
  ACMERequestHeaderSchema,
  ACMESignAlgorithmSchema,
  AuthorizationSchema,
  CertIDSchema,
  ChallengeSchema,
  DeactivateAccountSchema,
  DeactivateAuthorizationSchema,
  DirectoryMetaSchema,
  DirectorySchema,
  FinalizeSchema,
  FlattenedJWSSchema,
  IdentifierSchema,
  JWKSchema,
  JWSProtectedHeaderSchema,
  KeyChangeSchema,
  NewAccountSchema,
  NewAuthzSchema,
  NewOrderSchema,
  OrderSchema,
  ProblemSchema,
  RenewalInfoSchema,
  RevokeCertSchema,
  StrictIdentifierSchema,
  SubproblemSchema,
} from '..';

// -- strict schemas --

// FlattenedJWS
expectTypeOf<
  SchemaOutput<typeof FlattenedJWSSchema>
>().toExtend<FlattenedJWS>();
expectTypeOf<FlattenedJWS>().toExtend<
  SchemaOutput<typeof FlattenedJWSSchema>
>();

// JWSProtectedHeader
expectTypeOf<
  SchemaOutput<typeof JWSProtectedHeaderSchema>
>().toExtend<JWSProtectedHeader>();
expectTypeOf<JWSProtectedHeader>().toExtend<
  SchemaOutput<typeof JWSProtectedHeaderSchema>
>();

// ACMEProtectedHeader
expectTypeOf<
  SchemaOutput<typeof ACMEProtectedHeaderSchema>
>().toExtend<ACMEProtectedHeader>();
expectTypeOf<ACMEProtectedHeader>().toExtend<
  SchemaOutput<typeof ACMEProtectedHeaderSchema>
>();

// ACMERequestHeader
expectTypeOf<
  SchemaOutput<typeof ACMERequestHeaderSchema>
>().toExtend<ACMERequestHeader>();
expectTypeOf<ACMERequestHeader>().toExtend<
  SchemaOutput<typeof ACMERequestHeaderSchema>
>();

// ACMESignAlgorithm
expectTypeOf<
  SchemaOutput<typeof ACMESignAlgorithmSchema>
>().toExtend<ACMESignAlgorithm>();
expectTypeOf<ACMESignAlgorithm>().toExtend<
  SchemaOutput<typeof ACMESignAlgorithmSchema>
>();

// CertID
expectTypeOf<
  SchemaOutput<typeof CertIDSchema>
>().toExtend<CertID>();
expectTypeOf<CertID>().toExtend<
  SchemaOutput<typeof CertIDSchema>
>();

// Finalize
expectTypeOf<
  SchemaOutput<typeof FinalizeSchema>
>().toExtend<Finalize>();
expectTypeOf<Finalize>().toExtend<
  SchemaOutput<typeof FinalizeSchema>
>();

// RevokeCert
expectTypeOf<
  SchemaOutput<typeof RevokeCertSchema>
>().toExtend<RevokeCert>();
expectTypeOf<RevokeCert>().toExtend<
  SchemaOutput<typeof RevokeCertSchema>
>();

// DeactivateAccount
expectTypeOf<
  SchemaOutput<typeof DeactivateAccountSchema>
>().toExtend<DeactivateAccount>();
expectTypeOf<DeactivateAccount>().toExtend<
  SchemaOutput<typeof DeactivateAccountSchema>
>();

// DeactivateAuthorization
expectTypeOf<
  SchemaOutput<
    typeof DeactivateAuthorizationSchema
  >
>().toExtend<DeactivateAuthorization>();
expectTypeOf<DeactivateAuthorization>().toExtend<
  SchemaOutput<
    typeof DeactivateAuthorizationSchema
  >
>();

// KeyChange
expectTypeOf<
  SchemaOutput<typeof KeyChangeSchema>
>().toExtend<KeyChange>();
expectTypeOf<KeyChange>().toExtend<
  SchemaOutput<typeof KeyChangeSchema>
>();

// NewAccount
expectTypeOf<
  SchemaOutput<typeof NewAccountSchema>
>().toExtend<NewAccount>();
expectTypeOf<NewAccount>().toExtend<
  SchemaOutput<typeof NewAccountSchema>
>();

// NewAuthz
expectTypeOf<
  SchemaOutput<typeof NewAuthzSchema>
>().toExtend<NewAuthz>();
expectTypeOf<NewAuthz>().toExtend<
  SchemaOutput<typeof NewAuthzSchema>
>();

// NewOrder
expectTypeOf<
  SchemaOutput<typeof NewOrderSchema>
>().toExtend<NewOrder>();
expectTypeOf<NewOrder>().toExtend<
  SchemaOutput<typeof NewOrderSchema>
>();

// StrictIdentifier
expectTypeOf<
  SchemaOutput<typeof StrictIdentifierSchema>
>().toExtend<Identifier>();
expectTypeOf<Identifier>().toExtend<
  SchemaOutput<typeof StrictIdentifierSchema>
>();

// -- looseObject schemas --

// Identifier
expectTypeOf<
  SchemaOutput<typeof IdentifierSchema>
>().toExtend<Identifier>();
expectTypeOf<Identifier>().toExtend<
  SchemaOutput<typeof IdentifierSchema>
>();

// Subproblem
expectTypeOf<
  SchemaOutput<typeof SubproblemSchema>
>().toExtend<Subproblem>();
expectTypeOf<Subproblem>().toExtend<
  SchemaOutput<typeof SubproblemSchema>
>();
// RFC 8555 §6.7.1: subproblems MAY carry `identifier`.
expectTypeOf<Subproblem>().toHaveProperty('identifier');

// Problem
expectTypeOf<
  SchemaOutput<typeof ProblemSchema>
>().toExtend<Problem>();
expectTypeOf<Problem>().toExtend<
  SchemaOutput<typeof ProblemSchema>
>();
// RFC 8555 §6.7.1: identifier MUST NOT appear at top level of
// an ACME problem document. Locked in at the type layer; the
// schema's `looseObject` cannot enforce this at runtime
// without breaking RFC 7807 §3.2 extension passthrough.
expectTypeOf<Problem>().not.toHaveProperty('identifier');

// RenewalInfo
expectTypeOf<
  SchemaOutput<typeof RenewalInfoSchema>
>().toExtend<RenewalInfo>();
expectTypeOf<RenewalInfo>().toExtend<
  SchemaOutput<typeof RenewalInfoSchema>
>();

// Account
expectTypeOf<
  SchemaOutput<typeof AccountSchema>
>().toExtend<Account>();
expectTypeOf<Account>().toExtend<
  SchemaOutput<typeof AccountSchema>
>();

// Order
expectTypeOf<
  SchemaOutput<typeof OrderSchema>
>().toExtend<Order>();
expectTypeOf<Order>().toExtend<
  SchemaOutput<typeof OrderSchema>
>();

// Directory
expectTypeOf<
  SchemaOutput<typeof DirectorySchema>
>().toExtend<Directory>();
expectTypeOf<Directory>().toExtend<
  SchemaOutput<typeof DirectorySchema>
>();

// DirectoryMeta
expectTypeOf<
  SchemaOutput<typeof DirectoryMetaSchema>
>().toExtend<DirectoryMeta>();
expectTypeOf<DirectoryMeta>().toExtend<
  SchemaOutput<typeof DirectoryMetaSchema>
>();

// Challenge
expectTypeOf<
  SchemaOutput<typeof ChallengeSchema>
>().toExtend<Challenge>();
expectTypeOf<Challenge>().toExtend<
  SchemaOutput<typeof ChallengeSchema>
>();

// Authorization
expectTypeOf<
  SchemaOutput<typeof AuthorizationSchema>
>().toExtend<Authorization>();
expectTypeOf<Authorization>().toExtend<
  SchemaOutput<typeof AuthorizationSchema>
>();

// JWK
expectTypeOf<
  SchemaOutput<typeof JWKSchema>
>().toExtend<JWK>();
expectTypeOf<JWK>().toExtend<
  SchemaOutput<typeof JWKSchema>
>();
