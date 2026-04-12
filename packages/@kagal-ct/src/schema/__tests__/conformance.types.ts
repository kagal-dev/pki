// Schema ↔ type conformance — compile-time assertions.
// If schema and hand-written type drift, tsc fails.

import { expectTypeOf } from 'vitest';

import type { SchemaOutput } from './test-utils';

import type { Base64 } from '../../types/encoding';

import type {
  ConsistencyProof,
  InclusionProof,
  LogEntry,
  SignedCertificateTimestamp,
  SignedTreeHead,
  SubmittedEntry,
} from '../../types/ct';

import type {
  Base64Schema,
  ConsistencyProofSchema,
  InclusionProofSchema,
  LogEntrySchema,
  SignedCertificateTimestampSchema,
  SignedTreeHeadSchema,
  SubmittedEntrySchema,
} from '..';

// Base64
expectTypeOf<
  SchemaOutput<typeof Base64Schema>
>().toExtend<Base64>();
expectTypeOf<Base64>().toExtend<
  SchemaOutput<typeof Base64Schema>
>();

// SignedTreeHead
expectTypeOf<
  SchemaOutput<typeof SignedTreeHeadSchema>
>().toExtend<SignedTreeHead>();
expectTypeOf<SignedTreeHead>().toExtend<
  SchemaOutput<typeof SignedTreeHeadSchema>
>();

// SignedCertificateTimestamp
expectTypeOf<
  SchemaOutput<
    typeof SignedCertificateTimestampSchema
  >
>().toExtend<SignedCertificateTimestamp>();
expectTypeOf<SignedCertificateTimestamp>().toExtend<
  SchemaOutput<
    typeof SignedCertificateTimestampSchema
  >
>();

// SubmittedEntry
expectTypeOf<
  SchemaOutput<typeof SubmittedEntrySchema>
>().toExtend<SubmittedEntry>();
expectTypeOf<SubmittedEntry>().toExtend<
  SchemaOutput<typeof SubmittedEntrySchema>
>();

// LogEntry
expectTypeOf<
  SchemaOutput<typeof LogEntrySchema>
>().toExtend<LogEntry>();
expectTypeOf<LogEntry>().toExtend<
  SchemaOutput<typeof LogEntrySchema>
>();

// InclusionProof
expectTypeOf<
  SchemaOutput<typeof InclusionProofSchema>
>().toExtend<InclusionProof>();
expectTypeOf<InclusionProof>().toExtend<
  SchemaOutput<typeof InclusionProofSchema>
>();

// ConsistencyProof
expectTypeOf<
  SchemaOutput<typeof ConsistencyProofSchema>
>().toExtend<ConsistencyProof>();
expectTypeOf<ConsistencyProof>().toExtend<
  SchemaOutput<typeof ConsistencyProofSchema>
>();
