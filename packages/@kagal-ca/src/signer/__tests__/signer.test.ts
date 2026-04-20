// SignerDO implementation tests — DO instantiation,
// SQLite schema, internal state persistence. Interface
// contract tests live in `server/__tests__/signer.test.ts`.

import { jwkThumbprint } from '@kagal/acme/utils';
import { env, runInDurableObject } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';

const newSigner = (name = 'test-signer') => env.CA_SIGNER.get(
  env.CA_SIGNER.idFromName(name),
);

describe('SignerDO', () => {
  it('can be instantiated', async () => {
    await runInDurableObject(newSigner(), (instance) => {
      expect(instance).toBeDefined();
    });
  });

  it('has SQLite storage', async () => {
    await runInDurableObject(newSigner(), (_instance, state) => {
      expect(state.storage.sql).toBeDefined();
    });
  });

  describe('key management', () => {
    it('persists the key in SQLite', async () => {
      const stub = newSigner('persist');
      const key1 = await stub.getPublicKey();

      // Verify stored in SQLite
      await runInDurableObject(stub, (_instance, state) => {
        const rows = state.storage.sql
          .exec('SELECT version, kek_version, public_jwk FROM signing_keys')
          .toArray();
        expect(rows.length).toBe(1);
        expect(rows[0].version).toBe(1);
        expect(rows[0].kek_version).toBe(1);

        const storedPub = JSON.parse(rows[0].public_jwk as string);
        expect(storedPub).toEqual(key1);
      });
    });

    it('persists kid as the RFC 7638 thumbprint', async () => {
      const stub = newSigner('persist-kid');
      const pub = await stub.getPublicKey();
      const expected = await jwkThumbprint(
        pub as Parameters<typeof jwkThumbprint>[0],
      );

      await runInDurableObject(stub, (_instance, state) => {
        const rows = state.storage.sql
          .exec('SELECT kid FROM signing_keys')
          .toArray();
        expect(rows.length).toBe(1);
        expect(rows[0].kid).toBe(expected);
      });
    });

    it('persists chain_pem as NULL until 0c populates it', async () => {
      const stub = newSigner('persist-chain');
      await stub.getPublicKey();

      await runInDurableObject(stub, (_instance, state) => {
        const rows = state.storage.sql
          .exec('SELECT chain_pem FROM signing_keys')
          .toArray();
        expect(rows.length).toBe(1);
        expect(rows[0].chain_pem).toBeNull();
      });
    });

    it('rejects duplicate kid via UNIQUE constraint', async () => {
      const stub = newSigner('unique-kid');
      await stub.getPublicKey(); // bootstrap real row

      await runInDurableObject(stub, (_instance, state) => {
        const [existing] = state.storage.sql
          .exec(
            'SELECT wrapped_key, wrap_iv, kek_version,' +
            ' algorithm, public_jwk, kid FROM signing_keys',
          )
          .toArray();

        expect(() => state.storage.sql.exec(
          'INSERT INTO signing_keys' +
          ' (wrapped_key, wrap_iv, kek_version, algorithm,' +
          '  public_jwk, kid)' +
          ' VALUES (?, ?, ?, ?, ?, ?)',
          existing.wrapped_key,
          existing.wrap_iv,
          existing.kek_version,
          existing.algorithm,
          existing.public_jwk,
          existing.kid,
        )).toThrow(/UNIQUE/i);
      });
    });
  });

  describe('sign offsets (Phase 0a — pre-rotation)', () => {
    it('accepts offset 0 (alias for newest key)', async () => {
      const stub = newSigner('sign-offset-zero');
      const sig = await stub.sign(
        new TextEncoder().encode('x'), 0,
      );
      expect(sig).toBeInstanceOf(ArrayBuffer);
    });

    it('rejects negative offsets pending rotation', async () => {
      const stub = newSigner('sign-negative-offset');
      const data = new TextEncoder().encode('x');
      // Negative offsets reserve the historical-key
      // selection path — gated until rotation lands.
      // Attach the .catch synchronously to suppress
      // workerd's unhandled-rejection log on the RPC
      // boundary.
      const result = await stub.sign(data, -1)
        .catch((error: unknown) => error);
      expect(result).toBeInstanceOf(Error);
      expect((result as Error).message).toMatch(/rotation|not yet/i);
    });
  });

  describe('serial numbers', () => {
    it('starts at 1', async () => {
      const serial = await newSigner('serial-start').nextSerialNumber();
      expect(serial).toBe(1);
    });

    it('increments monotonically', async () => {
      const stub = newSigner('serial-inc');
      const s1 = await stub.nextSerialNumber();
      const s2 = await stub.nextSerialNumber();
      const s3 = await stub.nextSerialNumber();
      expect(s1).toBe(1);
      expect(s2).toBe(2);
      expect(s3).toBe(3);
    });

    it('persists across getSigningKey calls', async () => {
      const stub = newSigner('serial-persist');

      // Issue some serials
      await stub.nextSerialNumber();
      const last = await stub.nextSerialNumber();

      // Verify stored in SQLite
      await runInDurableObject(stub, (_instance, state) => {
        const rows = state.storage.sql
          .exec('SELECT last_serial FROM serial_counter WHERE id = 1')
          .toArray();
        expect(rows.length).toBe(1);
        expect(rows[0].last_serial).toBe(last);
      });
    });
  });
});
