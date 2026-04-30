import { describe, expect, it } from 'vitest';

import {
  TAI64N_CONTENT_LENGTH,
  TAI64N_CONTENT_TYPE,
  TAI64N_HEADER_KEY_SELECTOR,
  TAI64N_HEADER_LEAP_SECONDS,
  TAI64N_HEADER_NONCE,
  TAI64N_HEADER_SIGNATURE,
  TAI64N_PATH,
  TAI_OFFSET,
} from '../const';
import {
  newTaiclockHandler,
  taiclockSignedPayload,
} from '../handler';
import { newEd25519Signer } from '../signer';

const baseURL = `https://example.com${TAI64N_PATH}`;

const decodeBase64url = (value: string): ArrayBuffer => {
  // `atob` is forgiving about missing `=` padding per
  // the HTML spec — no re-padding needed.
  const standard = value.replaceAll('-', '+').replaceAll('_', '/');
  const bytes = Uint8Array.from(atob(standard), (c) => c.codePointAt(0) ?? 0);
  return bytes.buffer as ArrayBuffer;
};

const newKeypair = async (): Promise<CryptoKeyPair> =>
  await crypto.subtle.generateKey(
    'Ed25519',
    true,
    ['sign', 'verify'],
  ) as CryptoKeyPair;

describe('newTaiclockHandler', () => {
  describe('unsigned (no signer configured)', () => {
    const handler = newTaiclockHandler();

    it('returns a 25-byte TAI64N label on GET', async () => {
      const response = await handler(new Request(baseURL));

      expect(response.status).toBe(200);
      expect(response.headers.get('content-type')).toBe(TAI64N_CONTENT_TYPE);
      expect(response.headers.get('content-length'))
        .toBe(String(TAI64N_CONTENT_LENGTH));
      expect(response.headers.get('cache-control')).toBe('no-store');
      expect(response.headers.get(TAI64N_HEADER_LEAP_SECONDS))
        .toBe(String(TAI_OFFSET));

      const body = await response.text();
      expect(body).toMatch(/^@[0-9a-f]{24}$/);
      expect(body).toHaveLength(TAI64N_CONTENT_LENGTH);
    });

    it('omits the body on HEAD but keeps the headers', async () => {
      const response = await handler(
        new Request(baseURL, { method: 'HEAD' }),
      );

      expect(response.status).toBe(200);
      expect(response.headers.get('content-length'))
        .toBe(String(TAI64N_CONTENT_LENGTH));
      expect(response.headers.get('content-type')).toBe(TAI64N_CONTENT_TYPE);
      expect(await response.text()).toBe('');
    });

    it('echoes a TAI-Nonce header when present', async () => {
      const nonce = 'opaque-client-nonce';
      const response = await handler(new Request(baseURL, {
        headers: { [TAI64N_HEADER_NONCE]: nonce },
      }));

      expect(response.headers.get(TAI64N_HEADER_NONCE)).toBe(nonce);
      expect(response.headers.get(TAI64N_HEADER_SIGNATURE)).toBeNull();
    });

    it('omits TAI-Nonce when the request did not send one', async () => {
      const response = await handler(new Request(baseURL));

      expect(response.headers.get(TAI64N_HEADER_NONCE)).toBeNull();
      expect(response.headers.get(TAI64N_HEADER_SIGNATURE)).toBeNull();
    });

    it('returns 405 for non-GET/HEAD methods', async () => {
      for (const method of ['POST', 'PUT', 'DELETE', 'PATCH']) {
        const response = await handler(new Request(baseURL, { method }));
        expect(response.status).toBe(405);
        expect(response.headers.get('allow')).toBe('GET, HEAD');
      }
    });
  });

  describe('signed (signer configured)', () => {
    const selector = '2026q2';

    it('adds verifiable TAI-Signature + TAI-Key-Selector when nonce present', async () => {
      const { privateKey, publicKey } = await newKeypair();
      const handler = newTaiclockHandler({
        selector,
        signer: newEd25519Signer(privateKey),
      });
      const nonce = 'fresh-client-nonce';

      const response = await handler(new Request(baseURL, {
        headers: { [TAI64N_HEADER_NONCE]: nonce },
      }));

      const label = await response.text();
      const signature = response.headers.get(TAI64N_HEADER_SIGNATURE);
      expect(signature).not.toBeNull();
      expect(response.headers.get(TAI64N_HEADER_KEY_SELECTOR)).toBe(selector);
      expect(response.headers.get(TAI64N_HEADER_NONCE)).toBe(nonce);

      const leapSeconds = Number(
        response.headers.get(TAI64N_HEADER_LEAP_SECONDS),
      );
      const message = taiclockSignedPayload(
        label,
        leapSeconds,
        selector,
        nonce,
      );
      const valid = await crypto.subtle.verify(
        'Ed25519',
        publicKey,
        decodeBase64url(signature!),
        message,
      );
      expect(valid).toBe(true);
    });

    it('omits TAI-Signature and TAI-Key-Selector when no nonce is sent', async () => {
      const { privateKey } = await newKeypair();
      const handler = newTaiclockHandler({
        selector,
        signer: newEd25519Signer(privateKey),
      });

      const response = await handler(new Request(baseURL));

      expect(response.headers.get(TAI64N_HEADER_SIGNATURE)).toBeNull();
      expect(response.headers.get(TAI64N_HEADER_KEY_SELECTOR)).toBeNull();
      expect(response.headers.get(TAI64N_HEADER_NONCE)).toBeNull();
    });

    it('signature does not verify against a tampered nonce', async () => {
      const { privateKey, publicKey } = await newKeypair();
      const handler = newTaiclockHandler({
        selector,
        signer: newEd25519Signer(privateKey),
      });
      const nonce = 'real-nonce';

      const response = await handler(new Request(baseURL, {
        headers: { [TAI64N_HEADER_NONCE]: nonce },
      }));

      const label = await response.text();
      const signature = response.headers.get(TAI64N_HEADER_SIGNATURE)!;
      const tampered = taiclockSignedPayload(
        label,
        TAI_OFFSET,
        selector,
        'forged-nonce',
      );

      const valid = await crypto.subtle.verify(
        'Ed25519',
        publicKey,
        decodeBase64url(signature),
        tampered,
      );
      expect(valid).toBe(false);
    });

    it('signature does not verify against a tampered leap-seconds count', async () => {
      const { privateKey, publicKey } = await newKeypair();
      const handler = newTaiclockHandler({
        selector,
        signer: newEd25519Signer(privateKey),
      });
      const nonce = 'n';

      const response = await handler(new Request(baseURL, {
        headers: { [TAI64N_HEADER_NONCE]: nonce },
      }));

      const label = await response.text();
      const signature = response.headers.get(TAI64N_HEADER_SIGNATURE)!;
      const tampered = taiclockSignedPayload(
        label,
        TAI_OFFSET + 1,
        selector,
        nonce,
      );

      const valid = await crypto.subtle.verify(
        'Ed25519',
        publicKey,
        decodeBase64url(signature),
        tampered,
      );
      expect(valid).toBe(false);
    });

    it('signature does not verify against a tampered selector', async () => {
      const { privateKey, publicKey } = await newKeypair();
      const handler = newTaiclockHandler({
        selector,
        signer: newEd25519Signer(privateKey),
      });
      const nonce = 'n';

      const response = await handler(new Request(baseURL, {
        headers: { [TAI64N_HEADER_NONCE]: nonce },
      }));

      const label = await response.text();
      const signature = response.headers.get(TAI64N_HEADER_SIGNATURE)!;
      const tampered = taiclockSignedPayload(
        label,
        TAI_OFFSET,
        'attacker-selector',
        nonce,
      );

      const valid = await crypto.subtle.verify(
        'Ed25519',
        publicKey,
        decodeBase64url(signature),
        tampered,
      );
      expect(valid).toBe(false);
    });
  });

  describe('configuration', () => {
    it('throws when signer is set without selector', async () => {
      const { privateKey } = await newKeypair();
      expect(() => newTaiclockHandler({
        signer: newEd25519Signer(privateKey),
      })).toThrow(/signer and selector must be set together/);
    });

    it('throws when selector is set without signer', () => {
      expect(() => newTaiclockHandler({
        selector: 'orphan',
      })).toThrow(/signer and selector must be set together/);
    });

    it('throws on selector with invalid characters', async () => {
      const { privateKey } = await newKeypair();
      expect(() => newTaiclockHandler({
        selector: 'has spaces',
        signer: newEd25519Signer(privateKey),
      })).toThrow(/selector must match/);
    });

    it('throws on empty selector', async () => {
      const { privateKey } = await newKeypair();
      expect(() => newTaiclockHandler({
        selector: '',
        signer: newEd25519Signer(privateKey),
      })).toThrow(/selector must match/);
    });

    it('throws on selector longer than 63 chars', async () => {
      const { privateKey } = await newKeypair();
      expect(() => newTaiclockHandler({
        selector: 'a'.repeat(64),
        signer: newEd25519Signer(privateKey),
      })).toThrow(/selector must match/);
    });
  });
});

describe('taiclockSignedPayload', () => {
  it('frames as DOMAIN_SEPARATOR || label || leapU32BE || selectorLen || selector || nonce', () => {
    const label = '@4000000069f2594108a48640';
    const selector = '2026q2';
    const nonce = 'abc';
    const leap = 37;

    const view = new Uint8Array(
      taiclockSignedPayload(label, leap, selector, nonce),
    );

    const separator = new TextEncoder().encode('taiclock-v1\0');
    expect(view.slice(0, separator.length)).toEqual(separator);

    const labelBytes = new TextEncoder().encode(label);
    const labelStart = separator.length;
    expect(view.slice(labelStart, labelStart + labelBytes.length))
      .toEqual(labelBytes);

    const leapStart = labelStart + labelBytes.length;
    expect(view[leapStart]).toBe(0);
    expect(view[leapStart + 1]).toBe(0);
    expect(view[leapStart + 2]).toBe(0);
    expect(view[leapStart + 3]).toBe(leap);

    const selectorLengthStart = leapStart + 4;
    const selectorBytes = new TextEncoder().encode(selector);
    expect(view[selectorLengthStart]).toBe(selectorBytes.length);

    const selectorStart = selectorLengthStart + 1;
    expect(view.slice(selectorStart, selectorStart + selectorBytes.length))
      .toEqual(selectorBytes);

    const nonceBytes = new TextEncoder().encode(nonce);
    expect(view.slice(selectorStart + selectorBytes.length))
      .toEqual(nonceBytes);
  });
});
