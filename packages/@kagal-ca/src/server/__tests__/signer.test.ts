// Interface-contract tests for the Signer interface.
// Any impl wired to the `CA_SIGNER` binding should
// satisfy these — not SignerDO-specific.

import { env } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';

const ECDSA_P256 = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const ECDSA_SIGN = { name: 'ECDSA', hash: 'SHA-256' } as const;

const newSigner = (name = 'test-signer') => env.CA_SIGNER.get(
  env.CA_SIGNER.idFromName(name),
);

describe('Signer interface', () => {
  describe('key management', () => {
    it('generates a signing key on first access', async () => {
      const pub = await newSigner('keygen').getPublicKey();
      expect(pub.kty).toBe('EC');
      expect(pub.crv).toBe('P-256');
      expect(pub.x).toBeDefined();
      expect(pub.y).toBeDefined();
      // No private key material exposed
      expect(pub.d).toBeUndefined();
    });

    it('returns the same key on subsequent calls', async () => {
      const stub = newSigner('stable');
      const key1 = await stub.getPublicKey();
      const key2 = await stub.getPublicKey();
      expect(key1).toEqual(key2);
    });

    it('can sign and verify with the key', async () => {
      const stub = newSigner('sign-verify');
      const data = new TextEncoder().encode('test data');

      const [pub, signature] = await Promise.all([
        stub.getPublicKey(),
        stub.sign(data),
      ]);

      expect(signature).toBeInstanceOf(ArrayBuffer);
      expect(signature.byteLength).toBeGreaterThan(0);

      // Verify outside the DO — dull operation
      const verifyKey = await crypto.subtle.importKey(
        'jwk', pub, ECDSA_P256, false, ['verify'],
      );
      const valid = await crypto.subtle.verify(
        ECDSA_SIGN, verifyKey, signature, data,
      );
      expect(valid).toBe(true);
    });

    it('rejects positive sign offsets — no key newer than latest', async () => {
      const stub = newSigner('sign-positive-offset');
      const data = new TextEncoder().encode('x');
      // Attach the .catch synchronously to keep the
      // RPC rejection from surfacing as an unhandled
      // rejection in the worker before the caller can
      // consume it.
      const result = await stub.sign(data, 1)
        .catch((error: unknown) => error);
      expect(result).toBeInstanceOf(Error);
      expect((result as Error).message).toMatch(/invalid/i);
    });
  });
});
