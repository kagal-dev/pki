// parseCSR tests (RFC 2986, RFC 8555 §7.4).

import { afterEach, describe, expect, it, vi } from 'vitest';

import { decodePEM, encodePEM, parseCSR } from '..';
import { ProblemError } from '../../error';
import { asPEM } from '../../types';
import * as jwkModule from '../jwk';
import {
  Pkcs10CertificateRequestGenerator,
  SubjectAlternativeNameExtension,
} from '../x509';

vi.mock('../jwk', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../jwk')>();
  return {
    ...actual,
    exportJWK: vi.fn(actual.exportJWK),
  };
});

// Capture the passthrough set by `vi.fn(actual.exportJWK)`
// so `afterEach` can reinstate it after each test resets
// the mock. Tests can stage a one-shot override (e.g.
// `mockRejectedValueOnce`) without worrying about consuming
// it — the queue is cleared between tests regardless, and
// the next test starts with a clean passthrough.
const exportJWKMock = vi.mocked(jwkModule.exportJWK);
const passthroughImpl = exportJWKMock.getMockImplementation();

afterEach(() => {
  exportJWKMock.mockReset();
  if (passthroughImpl) {
    exportJWKMock.mockImplementation(passthroughImpl);
  }
});

const BAD_CSR_URN = 'urn:ietf:params:acme:error:badCSR';
const BAD_PUBLIC_KEY_URN = 'urn:ietf:params:acme:error:badPublicKey';
const COMPOUND_URN = 'urn:ietf:params:acme:error:compound';
const MALFORMED_URN = 'urn:ietf:params:acme:error:malformed';
const UNSUPPORTED_IDENTIFIER_URN =
  'urn:ietf:params:acme:error:unsupportedIdentifier';

async function expectProblem(
  promise: Promise<unknown>,
  expectedType: string,
): Promise<ProblemError> {
  try {
    await promise;
    expect.fail('expected ProblemError to be thrown');
  } catch (error) {
    expect(error).toBeInstanceOf(ProblemError);
    const problem = (error as ProblemError).problem;
    expect(problem.type).toBe(expectedType);
    return error as ProblemError;
  }
  // Unreachable — expect.fail throws above.
  throw new Error('unreachable');
}

const ECDSA_P256 = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const ECDSA_SIGN = { name: 'ECDSA', hash: 'SHA-256' } as const;
const ED25519 = { name: 'Ed25519' } as const;
const RSA_2048 = {
  hash: 'SHA-256',
  modulusLength: 2048,
  name: 'RSASSA-PKCS1-v1_5',
  publicExponent: new Uint8Array([1, 0, 1]),
} as const;

/**
 * Algorithm matrix the {@link parseCSR} round-trip
 * checks exercise. Mirrors the production reach of
 * `exportJWK` (jose covers `EC`, `OKP`, and `RSA`).
 */
const ALGORITHMS = [
  {
    expectedKty: 'EC',
    keygen: ECDSA_P256,
    label: 'ECDSA P-256',
    sign: ECDSA_SIGN,
  },
  {
    expectedKty: 'OKP',
    keygen: ED25519,
    label: 'Ed25519',
    sign: ED25519,
  },
  {
    expectedKty: 'RSA',
    keygen: RSA_2048,
    label: 'RSA-2048',
    sign: RSA_2048,
  },
] as const satisfies readonly {
  expectedKty: 'EC' | 'OKP' | 'RSA'
  keygen: Algorithm | EcKeyGenParams | RsaHashedKeyGenParams
  label: string
  sign: Algorithm | EcdsaParams | RsaHashedKeyGenParams
}[];

async function newCSR(options: {
  alg?: typeof ALGORITHMS[number]
  sans?: { type: 'dns' | 'email' | 'ip'; value: string }[]
  subject?: string
} = {}): Promise<string> {
  const alg = options.alg ?? ALGORITHMS[0];
  // generateKey returns `CryptoKey | CryptoKeyPair`
  // because the algorithm union spans symmetric and
  // asymmetric forms; every entry in `ALGORITHMS` is
  // asymmetric, so the cast is sound.
  const keys = (await crypto.subtle.generateKey(
    alg.keygen, true, ['sign', 'verify'],
  )) as CryptoKeyPair;
  const extensions = options.sans ?
    [new SubjectAlternativeNameExtension(options.sans)] :
    [];
  const csr = await Pkcs10CertificateRequestGenerator.create({
    name: options.subject ?? '',
    keys,
    signingAlgorithm: alg.sign,
    extensions,
  });
  return csr.toString('pem');
}

describe('parseCSR', () => {
  it('parses a valid CSR with DNS SANs', async () => {
    const pem = asPEM(await newCSR({
      sans: [
        { type: 'dns', value: 'example.com' },
        { type: 'dns', value: 'www.example.com' },
      ],
    }));
    const out = await parseCSR(pem);
    expect(out.sans).toEqual([
      { type: 'dns', value: 'example.com' },
      { type: 'dns', value: 'www.example.com' },
    ]);
    expect(out.subjectPublicKey.kty).toBe('EC');
    expect(out.der.byteLength).toBeGreaterThan(0);
  });

  it.each(ALGORITHMS)(
    'round-trips wire DER and subject JWK over $label',
    async (alg) => {
      const pem = asPEM(await newCSR({
        alg,
        sans: [{ type: 'dns', value: 'example.com' }],
      }));
      const out = await parseCSR(pem);
      expect(out.subjectPublicKey.kty).toBe(alg.expectedKty);
      expect(out.der).toEqual(decodePEM(pem, 'CERTIFICATE REQUEST'));
    },
  );

  it('parses a valid CSR with mixed dns + ip SANs', async () => {
    const pem = asPEM(await newCSR({
      sans: [
        { type: 'dns', value: 'example.com' },
        { type: 'ip', value: '192.0.2.1' },
      ],
    }));
    const out = await parseCSR(pem);
    expect(out.sans).toEqual([
      { type: 'dns', value: 'example.com' },
      { type: 'ip', value: '192.0.2.1' },
    ]);
  });

  it('returns an empty sans array when no SAN extension is present', async () => {
    const pem = asPEM(await newCSR({ subject: 'CN=example.com' }));
    const out = await parseCSR(pem);
    expect(out.sans).toEqual([]);
  });

  it('aggregates non-ACME SAN types into a compound problem', async () => {
    const pem = asPEM(await newCSR({
      sans: [
        { type: 'dns', value: 'example.com' },
        { type: 'email', value: 'me@example.com' },
        { type: 'email', value: 'admin@example.com' },
      ],
    }));
    const err = await expectProblem(parseCSR(pem), COMPOUND_URN);
    expect(err.problem.status).toBe(400);
    expect(err.problem.subproblems).toHaveLength(2);
    for (const sub of err.problem.subproblems ?? []) {
      expect(sub.type).toBe(UNSUPPORTED_IDENTIFIER_URN);
      expect(sub.identifier).toBeUndefined();
      expect(sub.detail).toMatch(/email/);
    }
  });

  it('rejects a CSR with a tampered signature as badCSR', async () => {
    const pem = await newCSR({
      sans: [{ type: 'dns', value: 'example.com' }],
    });
    // Flip a bit in the last 8 bytes (signature region) by
    // decoding the PEM body, mutating the DER, and
    // re-encoding with the same label.
    const body = pem
      .replace(/-----BEGIN CERTIFICATE REQUEST-----/, '')
      .replace(/-----END CERTIFICATE REQUEST-----/, '')
      .replaceAll(/\s+/g, '');
    const der = Uint8Array.from(
      // atob yields length-1 strings, so codePointAt(0) is defined.
      atob(body), (c) => c.codePointAt(0)!,
    );
    der[der.length - 4] ^= 0xFF;
    const tampered = encodePEM(der, 'CERTIFICATE REQUEST');
    const err = await expectProblem(parseCSR(tampered), BAD_CSR_URN);
    expect(err.problem.status).toBe(400);
    expect(err.problem.detail).toMatch(/proof-of-possession/);
  });

  it('rejects PEM with the wrong label as malformed', async () => {
    // Body is irrelevant — label mismatch fails first.
    const pem = encodePEM(new Uint8Array([1, 2, 3]), 'CERTIFICATE');
    const err = await expectProblem(parseCSR(pem), MALFORMED_URN);
    expect(err.problem.detail).toMatch(/label mismatch/);
  });

  it('rejects when subjectPublicKey export fails as badPublicKey', async () => {
    // exportJWK is mocked at module level with passthrough as
    // the default; this case overrides the next call to throw,
    // simulating a JWK export failure (unsupported curve,
    // non-extractable key, etc.) for a CSR that is otherwise
    // well-formed and PoP-verified.
    exportJWKMock.mockRejectedValueOnce(
      new TypeError('synthetic export failure'),
    );
    const pem = asPEM(await newCSR({
      sans: [{ type: 'dns', value: 'example.com' }],
    }));
    const err = await expectProblem(parseCSR(pem), BAD_PUBLIC_KEY_URN);
    expect(err.problem.status).toBe(400);
    expect(err.problem.detail).toMatch(/exported as a JWK/);
  });
});
