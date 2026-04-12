// Certificate Transparency schemas (RFC 9162)

import * as v from 'valibot';

import { Base64Schema } from './encoding';

/** Non-negative integer pipe. */
const nonNegInt = v.pipe(
  v.number(),
  v.integer(),
  v.minValue(0),
);

/** Positive integer pipe. */
const posInt = v.pipe(
  v.number(),
  v.integer(),
  v.minValue(1),
);

/** Log ID — base64 DER OID, 2–127 bytes (§4.4). */
const logID = v.pipe(
  Base64Schema,
  v.check(
    (s) => {
      const core = s.replace(/={1,2}$/, '');
      const bytes = Math.floor(core.length * 3 / 4);
      return bytes >= 2 && bytes <= 127;
    },
    'LogID must be 2–127 bytes',
  ),
);

/** Base64 NodeHash path array. */
const nodePath = v.array(Base64Schema);

/**
 * {@link SignedTreeHead} schema (RFC 9162 §4.10).
 *
 * @remarks
 * Uses `looseObject` — unknown fields pass through.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc9162#section-4.10}
 */
export const SignedTreeHeadSchema = v.looseObject({
  log_id: logID,
  root_hash: Base64Schema,
  signature: Base64Schema,
  timestamp: posInt,
  tree_size: nonNegInt,
});

/**
 * {@link SignedCertificateTimestamp} schema
 * (RFC 9162 §4.8).
 *
 * @remarks
 * Uses `looseObject` — unknown fields pass through.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc9162#section-4.8}
 */
export const SignedCertificateTimestampSchema =
  v.looseObject({
    log_id: logID,
    signature: Base64Schema,
    timestamp: posInt,
  });

/**
 * {@link SubmittedEntry} schema (RFC 9162 §5.1).
 *
 * @remarks
 * Uses `looseObject` — unknown fields pass through.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc9162#section-5.1}
 */
export const SubmittedEntrySchema = v.looseObject({
  chain: v.array(Base64Schema),
  submission: Base64Schema,
  type: posInt,
});

/**
 * {@link LogEntry} schema (RFC 9162 §5.6).
 *
 * @remarks
 * Uses `looseObject` — unknown fields pass through.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc9162#section-5.6}
 */
export const LogEntrySchema = v.looseObject({
  log_entry: Base64Schema,
  sct: Base64Schema,
  sth: Base64Schema,
  submitted_entry: SubmittedEntrySchema,
});

/**
 * {@link InclusionProof} schema (RFC 9162 §4.12).
 *
 * @remarks
 * Uses `looseObject` — unknown fields pass through.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc9162#section-4.12}
 */
export const InclusionProofSchema = v.pipe(
  v.looseObject({
    inclusion_path: nodePath,
    leaf_index: nonNegInt,
    log_id: logID,
    tree_size: posInt,
  }),
  v.check(
    (p) => p.leaf_index < p.tree_size,
    'leaf_index must be less than tree_size',
  ),
);

/**
 * {@link ConsistencyProof} schema
 * (RFC 9162 §4.11).
 *
 * @remarks
 * Uses `looseObject` — unknown fields pass through.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc9162#section-4.11}
 */
export const ConsistencyProofSchema = v.pipe(
  v.looseObject({
    consistency_path: nodePath,
    log_id: logID,
    tree_size_1: posInt,
    tree_size_2: posInt,
  }),
  v.check(
    (p) => p.tree_size_1 <= p.tree_size_2,
    'tree_size_1 must be <= tree_size_2',
  ),
);
