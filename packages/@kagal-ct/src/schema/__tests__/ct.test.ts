// CT schema tests (RFC 9162)

import { describe, expect, it } from 'vitest';

import {
  validateBase64,
  validateConsistencyProof,
  validateInclusionProof,
  validateLogEntry,
  validateSignedCertificateTimestamp,
  validateSignedTreeHead,
  validateSubmittedEntry,
} from '..';

describe('validateBase64', () => {
  it('accepts valid base64', () => {
    const result = validateBase64('dGVzdA==');
    expect(result.success).toBe(true);
  });

  it('accepts base64 without padding', () => {
    const result = validateBase64('dGVzdA');
    expect(result.success).toBe(true);
  });

  it('accepts base64 with + and /', () => {
    const result = validateBase64('a+b/cd==');
    expect(result.success).toBe(true);
  });

  it('rejects empty string', () => {
    const result = validateBase64('');
    expect(result.success).toBe(false);
  });

  it('rejects non-base64 characters', () => {
    const result = validateBase64('inv@lid!');
    expect(result.success).toBe(false);
  });

  it('rejects base64url characters (- and _)', () => {
    const result = validateBase64('a-b_cd');
    expect(result.success).toBe(false);
  });

  it('accepts single-pad (2 data bytes)', () => {
    const result = validateBase64('AAA=');
    expect(result.success).toBe(true);
  });

  it('accepts double-pad (1 data byte)', () => {
    const result = validateBase64('AA==');
    expect(result.success).toBe(true);
  });

  it('rejects invalid length (1 mod 4)', () => {
    const result = validateBase64('AAAAA');
    expect(result.success).toBe(false);
  });

  it('rejects malformed padding (not mod-4)', () => {
    const result = validateBase64('AA=');
    expect(result.success).toBe(false);
  });

  it('rejects mismatched padding (3-char core + ==)', () => {
    const result = validateBase64('AAA==');
    expect(result.success).toBe(false);
  });
});

describe('validateSignedTreeHead', () => {
  const valid = {
    log_id: 'bG9n',
    tree_size: 42,
    timestamp: 1_712_000_000_000,
    root_hash: 'dGVzdA',
    signature: 'c2ln',
  };

  it('accepts a valid STH', () => {
    const result = validateSignedTreeHead(valid);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.tree_size).toBe(42);
    }
  });

  it('accepts tree_size 0 (empty log)', () => {
    const result = validateSignedTreeHead({
      ...valid, tree_size: 0,
    });
    expect(result.success).toBe(true);
  });

  it('rejects negative tree_size', () => {
    const result = validateSignedTreeHead({
      ...valid, tree_size: -1,
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-integer tree_size', () => {
    const result = validateSignedTreeHead({
      ...valid, tree_size: 1.5,
    });
    expect(result.success).toBe(false);
  });

  it('rejects zero timestamp', () => {
    const result = validateSignedTreeHead({
      ...valid, timestamp: 0,
    });
    expect(result.success).toBe(false);
  });

  it('rejects empty root_hash', () => {
    const result = validateSignedTreeHead({
      ...valid, root_hash: '',
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-base64 signature', () => {
    const result = validateSignedTreeHead({
      ...valid, signature: 'inv@lid!',
    });
    expect(result.success).toBe(false);
  });

  it('rejects empty log_id', () => {
    const result = validateSignedTreeHead({
      ...valid, log_id: '',
    });
    expect(result.success).toBe(false);
  });

  it('rejects too-short log_id (< 2-byte OID)', () => {
    const result = validateSignedTreeHead({
      ...valid, log_id: 'AB',
    });
    expect(result.success).toBe(false);
  });

  it('rejects padded log_id below 2-byte minimum', () => {
    const result = validateSignedTreeHead({
      ...valid, log_id: 'AB==',
    });
    expect(result.success).toBe(false);
  });

  it('rejects log_id exceeding 127-byte maximum', () => {
    const result = validateSignedTreeHead({
      ...valid, log_id: 'A'.repeat(171),
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-base64 log_id', () => {
    const result = validateSignedTreeHead({
      ...valid, log_id: '@@@',
    });
    expect(result.success).toBe(false);
  });

  it('rejects missing fields', () => {
    const result = validateSignedTreeHead({});
    expect(result.success).toBe(false);
  });

  it('preserves unknown fields', () => {
    const result = validateSignedTreeHead({
      ...valid, extra: true,
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(
        (result.data as unknown as Record<string, unknown>).extra,
      ).toBe(true);
    }
  });
});

describe('validateSignedCertificateTimestamp', () => {
  const valid = {
    log_id: 'bG9n',
    timestamp: 1_712_000_000_000,
    signature: 'c2ln',
  };

  it('accepts a valid SCT', () => {
    const result =
      validateSignedCertificateTimestamp(valid);
    expect(result.success).toBe(true);
  });

  it('rejects empty log_id', () => {
    const result =
      validateSignedCertificateTimestamp({
        ...valid, log_id: '',
      });
    expect(result.success).toBe(false);
  });

  it('rejects too-short log_id (< 2-byte OID)', () => {
    const result =
      validateSignedCertificateTimestamp({
        ...valid, log_id: 'AB',
      });
    expect(result.success).toBe(false);
  });

  it('rejects non-base64 signature', () => {
    const result =
      validateSignedCertificateTimestamp({
        ...valid, signature: 'inv@lid!',
      });
    expect(result.success).toBe(false);
  });

  it('rejects missing fields', () => {
    const result =
      validateSignedCertificateTimestamp({});
    expect(result.success).toBe(false);
  });
});

describe('validateSubmittedEntry', () => {
  const valid = {
    submission: 'Y2VydA',
    type: 1,
    chain: ['Y2Ex', 'Y2Ey'],
  };

  it('accepts a valid entry', () => {
    const result = validateSubmittedEntry(valid);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.type).toBe(1);
      expect(result.data.chain).toHaveLength(2);
    }
  });

  it('accepts empty chain (self-signed)', () => {
    const result = validateSubmittedEntry({
      ...valid, chain: [],
    });
    expect(result.success).toBe(true);
  });

  it('rejects empty submission', () => {
    const result = validateSubmittedEntry({
      ...valid, submission: '',
    });
    expect(result.success).toBe(false);
  });

  it('rejects zero type', () => {
    const result = validateSubmittedEntry({
      ...valid, type: 0,
    });
    expect(result.success).toBe(false);
  });

  it('rejects empty string in chain', () => {
    const result = validateSubmittedEntry({
      ...valid, chain: ['Y2Ex', ''],
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-base64 submission', () => {
    const result = validateSubmittedEntry({
      ...valid, submission: 'inv@lid!',
    });
    expect(result.success).toBe(false);
  });

  it('rejects missing fields', () => {
    const result = validateSubmittedEntry({});
    expect(result.success).toBe(false);
  });
});

describe('validateLogEntry', () => {
  const valid = {
    log_entry: 'bGVhZg',
    sct: 'c2N0',
    sth: 'c3Ro',
    submitted_entry: {
      submission: 'Y2VydA',
      type: 1,
      chain: ['Y2Ex'],
    },
  };

  it('accepts a valid entry', () => {
    const result = validateLogEntry(valid);
    expect(result.success).toBe(true);
  });

  it('rejects empty log_entry', () => {
    const result = validateLogEntry({
      ...valid, log_entry: '',
    });
    expect(result.success).toBe(false);
  });

  it('rejects invalid submitted_entry', () => {
    const result = validateLogEntry({
      ...valid, submitted_entry: {},
    });
    expect(result.success).toBe(false);
  });

  it('rejects empty sct', () => {
    const result = validateLogEntry({
      ...valid, sct: '',
    });
    expect(result.success).toBe(false);
  });

  it('rejects empty sth', () => {
    const result = validateLogEntry({
      ...valid, sth: '',
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-base64 sth', () => {
    const result = validateLogEntry({
      ...valid, sth: 'inv@lid!',
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-base64 log_entry', () => {
    const result = validateLogEntry({
      ...valid, log_entry: 'inv@lid!',
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-base64 sct', () => {
    const result = validateLogEntry({
      ...valid, sct: 'inv@lid!',
    });
    expect(result.success).toBe(false);
  });

  it('rejects missing fields', () => {
    const result = validateLogEntry({});
    expect(result.success).toBe(false);
  });
});

describe('validateInclusionProof', () => {
  const valid = {
    log_id: 'bG9n',
    tree_size: 8,
    leaf_index: 3,
    inclusion_path: ['aGFzaDE', 'aGFzaDI', 'aGFzaDM'],
  };

  it('accepts a valid proof', () => {
    const result = validateInclusionProof(valid);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.inclusion_path).toHaveLength(3);
    }
  });

  it('accepts leaf_index 0', () => {
    const result = validateInclusionProof({
      ...valid, leaf_index: 0,
    });
    expect(result.success).toBe(true);
  });

  it('accepts empty inclusion_path (single-entry tree)', () => {
    const result = validateInclusionProof({
      ...valid, tree_size: 1, leaf_index: 0, inclusion_path: [],
    });
    expect(result.success).toBe(true);
  });

  it('rejects zero tree_size', () => {
    const result = validateInclusionProof({
      ...valid, tree_size: 0,
    });
    expect(result.success).toBe(false);
  });

  it('rejects leaf_index equal to tree_size', () => {
    const result = validateInclusionProof({
      ...valid, leaf_index: 8, tree_size: 8,
    });
    expect(result.success).toBe(false);
  });

  it('rejects leaf_index greater than tree_size', () => {
    const result = validateInclusionProof({
      ...valid, leaf_index: 10, tree_size: 8,
    });
    expect(result.success).toBe(false);
  });

  it('rejects negative leaf_index', () => {
    const result = validateInclusionProof({
      ...valid, leaf_index: -1,
    });
    expect(result.success).toBe(false);
  });

  it('rejects empty log_id', () => {
    const result = validateInclusionProof({
      ...valid, log_id: '',
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-base64 in inclusion_path', () => {
    const result = validateInclusionProof({
      ...valid, inclusion_path: ['inv@lid!'],
    });
    expect(result.success).toBe(false);
  });

  it('rejects missing fields', () => {
    const result = validateInclusionProof({});
    expect(result.success).toBe(false);
  });
});

describe('validateConsistencyProof', () => {
  const valid = {
    log_id: 'bG9n',
    tree_size_1: 4,
    tree_size_2: 8,
    consistency_path: ['aGFzaDE', 'aGFzaDI'],
  };

  it('accepts a valid proof', () => {
    const result = validateConsistencyProof(valid);
    expect(result.success).toBe(true);
  });

  it('accepts equal tree sizes', () => {
    const result = validateConsistencyProof({
      ...valid, tree_size_1: 8, tree_size_2: 8,
    });
    expect(result.success).toBe(true);
  });

  it('accepts empty consistency_path (identical trees)', () => {
    const result = validateConsistencyProof({
      ...valid, tree_size_1: 4, tree_size_2: 4, consistency_path: [],
    });
    expect(result.success).toBe(true);
  });

  it('rejects tree_size_1 greater than tree_size_2', () => {
    const result = validateConsistencyProof({
      ...valid, tree_size_1: 10, tree_size_2: 4,
    });
    expect(result.success).toBe(false);
  });

  it('rejects zero tree_size_1', () => {
    const result = validateConsistencyProof({
      ...valid, tree_size_1: 0,
    });
    expect(result.success).toBe(false);
  });

  it('rejects zero tree_size_2', () => {
    const result = validateConsistencyProof({
      ...valid, tree_size_2: 0,
    });
    expect(result.success).toBe(false);
  });

  it('rejects empty log_id', () => {
    const result = validateConsistencyProof({
      ...valid, log_id: '',
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-base64 in consistency_path', () => {
    const result = validateConsistencyProof({
      ...valid, consistency_path: ['inv@lid!'],
    });
    expect(result.success).toBe(false);
  });

  it('rejects missing fields', () => {
    const result = validateConsistencyProof({});
    expect(result.success).toBe(false);
  });
});
