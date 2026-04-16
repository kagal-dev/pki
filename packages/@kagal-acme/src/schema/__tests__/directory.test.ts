// Directory schema tests (RFC 8555 §7.1.1)

import { describe, expect, it } from 'vitest';

import {
  validateDirectory,
  validateDirectoryMeta,
} from '..';

const minimalDirectory = {
  newNonce: 'https://ca.example/acme/new-nonce',
  newAccount: 'https://ca.example/acme/new-acct',
  newOrder: 'https://ca.example/acme/new-order',
  revokeCert: 'https://ca.example/acme/revoke-cert',
  keyChange: 'https://ca.example/acme/key-change',
};

describe('validateDirectory', () => {
  it('accepts a minimal directory', () => {
    const result = validateDirectory(minimalDirectory);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.newNonce)
        .toBe('https://ca.example/acme/new-nonce');
    }
  });

  it('accepts with optional newAuthz', () => {
    const result = validateDirectory({
      ...minimalDirectory,
      newAuthz: 'https://ca.example/acme/new-authz',
    });
    expect(result.success).toBe(true);
  });

  it('accepts with meta', () => {
    const result = validateDirectory({
      ...minimalDirectory,
      meta: {
        termsOfService: 'https://ca.example/tos',
        website: 'https://ca.example',
        caaIdentities: ['ca.example'],
        externalAccountRequired: true,
      },
    });
    expect(result.success).toBe(true);
  });

  it('accepts with ARI renewalInfo', () => {
    const result = validateDirectory({
      ...minimalDirectory,
      renewalInfo: 'https://ca.example/acme/renewal-info',
    });
    expect(result.success).toBe(true);
  });

  it('accepts with Profiles in meta', () => {
    const result = validateDirectory({
      ...minimalDirectory,
      meta: {
        profiles: {
          'classic': 'Default profile',
          'tls-server': 'Modern TLS server',
          'short-lived': 'Short-lived certificate',
        },
      },
    });
    expect(result.success).toBe(true);
  });

  it('rejects missing required URLs', () => {
    const result = validateDirectory({
      newNonce: 'https://ca.example/acme/new-nonce',
      newAccount: 'https://ca.example/acme/new-acct',
    });
    expect(result.success).toBe(false);
  });

  it.each([
    'newNonce',
    'newAccount',
    'newOrder',
    'revokeCert',
    'keyChange',
  ] as const)(
    'rejects non-URL %s endpoint',
    (field) => {
      const result = validateDirectory({
        ...minimalDirectory,
        [field]: 'not a url',
      });
      expect(result.success).toBe(false);
    },
  );

  it('rejects non-URL newAuthz endpoint', () => {
    const result = validateDirectory({
      ...minimalDirectory,
      newAuthz: 'not a url',
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-URL renewalInfo', () => {
    const result = validateDirectory({
      ...minimalDirectory,
      renewalInfo: 'not a url',
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-URL termsOfService in meta', () => {
    const result = validateDirectory({
      ...minimalDirectory,
      meta: {
        termsOfService: 'not a url',
      },
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-URL website in meta', () => {
    const result = validateDirectory({
      ...minimalDirectory,
      meta: {
        website: 'not a url',
      },
    });
    expect(result.success).toBe(false);
  });

  it('preserves unknown fields', () => {
    const result = validateDirectory({
      ...minimalDirectory,
      newStarCert: 'https://ca.example/acme/new-star',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(
        (result.data as unknown as Record<string, unknown>)
          .newStarCert,
      ).toBe('https://ca.example/acme/new-star');
    }
  });
});

describe('validateDirectoryMeta', () => {
  it('accepts an empty meta', () => {
    const result = validateDirectoryMeta({});
    expect(result.success).toBe(true);
  });

  it('rejects non-object', () => {
    const result = validateDirectoryMeta('not-an-object');
    expect(result.success).toBe(false);
  });
});
