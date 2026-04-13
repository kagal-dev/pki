// Certificate Transparency types (RFC 9162)

import type { Base64 } from './encoding';

/**
 * Signed Tree Head (RFC 9162 §4.10).
 *
 * Flattens {@link https://datatracker.ietf.org/doc/html/rfc9162#section-4.9 | TreeHeadDataV2}
 * into the top level.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc9162#section-4.10}
 */
export interface SignedTreeHead {
  /** Log ID — base64-encoded DER-encoded OID (§4.4). */
  log_id: Base64
  /** Base64-encoded root hash. */
  root_hash: Base64
  /** Base64-encoded signature over the tree head. */
  signature: Base64
  /** Tree head timestamp (milliseconds since epoch). */
  timestamp: number
  /** Number of entries in the log. */
  tree_size: number
};

/**
 * Signed Certificate Timestamp (RFC 9162 §4.8).
 *
 * Signed promise from a log that a submitted entry
 * will be included within the Maximum Merge Delay.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc9162#section-4.8}
 */
export interface SignedCertificateTimestamp {
  /** Log ID — base64-encoded DER-encoded OID (§4.4). */
  log_id: Base64
  /** Base64-encoded signature. */
  signature: Base64
  /** Logging timestamp (milliseconds since epoch). */
  timestamp: number
};

/**
 * Submitted entry — mirrors submit-entry inputs
 * (RFC 9162 §5.1).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc9162#section-5.1}
 */
export interface SubmittedEntry {
  /** Base64-encoded CA certificates. */
  chain: Base64[]
  /** Base64-encoded certificate or precertificate. */
  submission: Base64
  /** VersionedTransType integer (§4.5). */
  type: number
};

/**
 * CT log entry from get-entries response
 * (RFC 9162 §5.6).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc9162#section-5.6}
 */
export interface LogEntry {
  /** Base64-encoded TransItem (x509_entry_v2 or precert_entry_v2, §4.3). */
  log_entry: Base64
  /** Base64-encoded SCT TransItem (§4.8). */
  sct: Base64
  /** Base64-encoded STH TransItem (§4.10). */
  sth: Base64
  /** Submitted entry — mirrors submit-entry inputs (§5.1). */
  submitted_entry: SubmittedEntry
};

/**
 * Merkle inclusion proof (RFC 9162 §4.12).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc9162#section-4.12}
 */
export interface InclusionProof {
  /** Base64-encoded sibling hashes on the path to the root. */
  inclusion_path: Base64[]
  /** Leaf index. */
  leaf_index: number
  /** Log ID — base64-encoded DER-encoded OID (§4.4). */
  log_id: Base64
  /** Tree size the proof is relative to. */
  tree_size: number
};

/**
 * Merkle consistency proof (RFC 9162 §4.11).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc9162#section-4.11}
 */
export interface ConsistencyProof {
  /** Base64-encoded hashes forming the proof. */
  consistency_path: Base64[]
  /** Log ID — base64-encoded DER-encoded OID (§4.4). */
  log_id: Base64
  /** Size of the older tree. */
  tree_size_1: number
  /** Size of the newer tree. */
  tree_size_2: number
};
