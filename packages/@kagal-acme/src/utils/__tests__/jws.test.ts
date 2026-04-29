// ACME JWS parse-and-verify tests (RFC 7515, RFC 8555 §6)

import { FlattenedSign, type FlattenedJWS as JoseFlattenedJWS } from 'jose';
import { describe, expect, it } from 'vitest';

import {
  decodeBase64url,
  encodeBase64url,
  exportJWK,
  getRandom,
  parseJWS,
  type ResolveKey,
} from '..';
import { ProblemError } from '../../error';
import {
  asBase64url,
  type ErrorType,
  type FlattenedJWS,
  type JWK,
} from '../../types';

type Keypair = {
  privateJWK: JWK
  publicJWK: JWK
};

async function newECKeypair(): Promise<Keypair> {
  const { privateKey, publicKey } = await crypto.subtle
    .generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    );
  return {
    privateJWK: await exportJWK(privateKey),
    publicJWK: await exportJWK(publicKey),
  };
}

async function newEdKeypair(): Promise<Keypair> {
  const { privateKey, publicKey } = await crypto.subtle
    .generateKey(
      { name: 'Ed25519' },
      true,
      ['sign', 'verify'],
    );
  return {
    privateJWK: await exportJWK(privateKey),
    publicJWK: await exportJWK(publicKey),
  };
}

async function newRSKeypair(): Promise<Keypair> {
  const { privateKey, publicKey } = await crypto.subtle
    .generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: 'SHA-256',
      },
      true,
      ['sign', 'verify'],
    );
  return {
    privateJWK: await exportJWK(privateKey),
    publicJWK: await exportJWK(publicKey),
  };
}

type SignArguments = {
  payload: unknown
  privateJWK: JWK
  protectedHeader: Record<string, unknown>
};

function toFlattenedJWS(signed: JoseFlattenedJWS): FlattenedJWS {
  return {
    protected: asBase64url(signed.protected ?? ''),
    payload: signed.payload === '' ?
      '' :
      asBase64url(signed.payload),
    signature: asBase64url(signed.signature),
  };
}

async function signJWS(arguments_: SignArguments): Promise<FlattenedJWS> {
  const bytes = arguments_.payload === undefined ?
    new Uint8Array() :
    new TextEncoder().encode(JSON.stringify(arguments_.payload));
  const signed = await new FlattenedSign(bytes)
    .setProtectedHeader(arguments_.protectedHeader)
    .sign(arguments_.privateJWK);
  return toFlattenedJWS(signed);
}

const URL_UNDER_TEST = 'https://ca.example/acme/new-order';

const ACCOUNT_DOES_NOT_EXIST: ErrorType =
  'urn:ietf:params:acme:error:accountDoesNotExist';
const BAD_SIGNATURE_ALGORITHM: ErrorType =
  'urn:ietf:params:acme:error:badSignatureAlgorithm';
const MALFORMED: ErrorType =
  'urn:ietf:params:acme:error:malformed';
const UNAUTHORIZED: ErrorType =
  'urn:ietf:params:acme:error:unauthorized';

function keyResolver(jwk: JWK): ResolveKey {
  return async () => jwk;
}

const failingResolver: ResolveKey = async () => {
  throw new Error('account deactivated');
};

async function expectProblem(
  promise: Promise<unknown>,
  type: ErrorType,
  detailMatch?: RegExp,
): Promise<ProblemError> {
  const error: unknown = await promise
    .catch((error_: unknown) => error_);
  expect(error).toBeInstanceOf(ProblemError);
  const pe = error as ProblemError;
  expect(pe.problem.type).toBe(type);
  if (detailMatch) {
    expect(pe.message).toMatch(detailMatch);
  }
  return pe;
}

async function expectHeaderRejection(
  overrides: Record<string, unknown>,
  type: ErrorType,
  detailMatch?: RegExp,
): Promise<ProblemError> {
  const { publicJWK } = await newECKeypair();
  const bad: FlattenedJWS = {
    protected: encodeBase64url(new TextEncoder().encode(JSON.stringify({
      alg: 'ES256',
      kid: 'https://ca.example/acme/acct/1',
      nonce: getRandom(16),
      url: URL_UNDER_TEST,
      ...overrides,
    }))),
    payload: asBase64url('eyJ9'),
    signature: asBase64url('AAAA'),
  };
  return expectProblem(
    parseJWS(bad, URL_UNDER_TEST, keyResolver(publicJWK)),
    type,
    detailMatch,
  );
}

describe('parseJWS', () => {
  it('round-trips a kid-signed request', async () => {
    const { privateJWK, publicJWK } = await newECKeypair();
    const jws = await signJWS({
      privateJWK,
      protectedHeader: {
        alg: 'ES256',
        kid: 'https://ca.example/acme/acct/1',
        nonce: getRandom(16),
        url: URL_UNDER_TEST,
      },
      payload: { identifiers: [{ type: 'dns', value: 'a.example' }] },
    });

    const parsed = await parseJWS(
      jws, URL_UNDER_TEST, keyResolver(publicJWK),
    );

    expect(parsed.protectedHeader.kid)
      .toBe('https://ca.example/acme/acct/1');
    expect(parsed.protectedHeader.jwk).toBeUndefined();
    expect(parsed.protectedHeader.url).toBe(URL_UNDER_TEST);
    expect(parsed.payload).toEqual({
      identifiers: [{ type: 'dns', value: 'a.example' }],
    });
    expect(parsed.jws).toStrictEqual(jws);
  });

  it('round-trips a jwk-signed request (newAccount)', async () => {
    const { privateJWK, publicJWK } = await newECKeypair();
    const jws = await signJWS({
      privateJWK,
      protectedHeader: {
        alg: 'ES256',
        jwk: publicJWK,
        nonce: getRandom(16),
        url: URL_UNDER_TEST,
      },
      payload: { termsOfServiceAgreed: true },
    });

    const parsed = await parseJWS(
      jws, URL_UNDER_TEST, keyResolver(publicJWK),
    );

    expect(parsed.protectedHeader.jwk).toEqual(publicJWK);
    expect(parsed.protectedHeader.kid).toBeUndefined();
    expect(parsed.payload).toEqual({ termsOfServiceAgreed: true });
  });

  it('accepts POST-as-GET (empty payload)', async () => {
    const { privateJWK, publicJWK } = await newECKeypair();
    const jws = await signJWS({
      privateJWK,
      protectedHeader: {
        alg: 'ES256',
        kid: 'https://ca.example/acme/acct/1',
        nonce: getRandom(16),
        url: URL_UNDER_TEST,
      },
      payload: undefined,
    });

    const parsed = await parseJWS(
      jws, URL_UNDER_TEST, keyResolver(publicJWK),
    );

    expect(parsed.payload).toBeUndefined();
    expect(parsed.jws.payload).toBe('');
  });

  it('round-trips an EdDSA-signed request', async () => {
    const { privateJWK, publicJWK } = await newEdKeypair();
    const jws = await signJWS({
      privateJWK,
      protectedHeader: {
        alg: 'EdDSA',
        kid: 'https://ca.example/acme/acct/1',
        nonce: getRandom(16),
        url: URL_UNDER_TEST,
      },
      payload: { identifiers: [{ type: 'dns', value: 'a.example' }] },
    });

    const parsed = await parseJWS(
      jws, URL_UNDER_TEST, keyResolver(publicJWK),
    );

    expect(parsed.protectedHeader.kid)
      .toBe('https://ca.example/acme/acct/1');
    expect(parsed.payload).toEqual({
      identifiers: [{ type: 'dns', value: 'a.example' }],
    });
  });

  it('round-trips an RS256-signed request', async () => {
    const { privateJWK, publicJWK } = await newRSKeypair();
    const jws = await signJWS({
      privateJWK,
      protectedHeader: {
        alg: 'RS256',
        kid: 'https://ca.example/acme/acct/1',
        nonce: getRandom(16),
        url: URL_UNDER_TEST,
      },
      payload: { identifiers: [{ type: 'dns', value: 'a.example' }] },
    });

    const parsed = await parseJWS(
      jws, URL_UNDER_TEST, keyResolver(publicJWK),
    );

    expect(parsed.protectedHeader.kid)
      .toBe('https://ca.example/acme/acct/1');
    expect(parsed.payload).toEqual({
      identifiers: [{ type: 'dns', value: 'a.example' }],
    });
  });

  it('rejects an outer JWS missing required fields', async () => {
    const { publicJWK } = await newECKeypair();
    await expectProblem(
      parseJWS(
        { protected: 'AAAA', payload: '' },
        URL_UNDER_TEST,
        keyResolver(publicJWK),
      ),
      MALFORMED,
      /invalid Flattened JWS/,
    );
  });

  it('rejects a non-object body', async () => {
    const { publicJWK } = await newECKeypair();
    await expectProblem(
      parseJWS('not a jws', URL_UNDER_TEST, keyResolver(publicJWK)),
      MALFORMED,
      /invalid Flattened JWS/,
    );
  });

  it('rejects a protected header that is not valid JSON', async () => {
    const { privateJWK, publicJWK } = await newECKeypair();
    const jws = await signJWS({
      privateJWK,
      protectedHeader: {
        alg: 'ES256',
        kid: 'https://ca.example/acme/acct/1',
        nonce: getRandom(16),
        url: URL_UNDER_TEST,
      },
      payload: {},
    });
    const tampered: FlattenedJWS = {
      ...jws,
      protected: encodeBase64url(new TextEncoder().encode('{not-json')),
    };
    await expectProblem(
      parseJWS(tampered, URL_UNDER_TEST, keyResolver(publicJWK)),
      MALFORMED,
      /protected header is not valid JSON/,
    );
  });

  it('rejects a protected header missing required ACME fields', async () => {
    const { privateJWK, publicJWK } = await newECKeypair();
    const jws = await signJWS({
      privateJWK,
      protectedHeader: { alg: 'ES256' },
      payload: {},
    });
    await expectProblem(
      parseJWS(jws, URL_UNDER_TEST, keyResolver(publicJWK)),
      MALFORMED,
      /invalid ACME protected header/,
    );
  });

  it('rejects a jwk + kid header (mutually exclusive)', async () => {
    const { privateJWK, publicJWK } = await newECKeypair();
    const jws = await signJWS({
      privateJWK,
      protectedHeader: {
        alg: 'ES256',
        jwk: publicJWK,
        kid: 'https://ca.example/acme/acct/1',
        nonce: getRandom(16),
        url: URL_UNDER_TEST,
      },
      payload: {},
    });
    await expectProblem(
      parseJWS(jws, URL_UNDER_TEST, keyResolver(publicJWK)),
      MALFORMED,
      /invalid ACME protected header/,
    );
  });

  it('rejects alg: HS256 on outer JWS (MAC forbidden)', () =>
    expectHeaderRejection(
      { alg: 'HS256' },
      BAD_SIGNATURE_ALGORITHM,
      /unsupported JWS signature algorithm: HS256/,
    ),
  );

  it('rejects alg: none on outer JWS', () =>
    expectHeaderRejection(
      { alg: 'none' },
      BAD_SIGNATURE_ALGORITHM,
      /unsupported JWS signature algorithm: none/,
    ),
  );

  it('rejects an unregistered alg', () =>
    expectHeaderRejection(
      { alg: 'XYZ123' },
      BAD_SIGNATURE_ALGORITHM,
      /unsupported JWS signature algorithm: XYZ123/,
    ),
  );

  it('rejects a non-string alg (number)', () =>
    expectHeaderRejection(
      { alg: 256 },
      BAD_SIGNATURE_ALGORITHM,
      /unsupported JWS signature algorithm: 256/,
    ),
  );

  it('rejects non-URL kid', () =>
    expectHeaderRejection(
      { kid: 'acct/1' },
      MALFORMED,
      /invalid ACME protected header/,
    ),
  );

  it('rejects empty nonce', () =>
    expectHeaderRejection(
      { nonce: '' },
      MALFORMED,
      /invalid ACME protected header/,
    ),
  );

  it('rejects url mismatch', async () => {
    const { privateJWK, publicJWK } = await newECKeypair();
    const jws = await signJWS({
      privateJWK,
      protectedHeader: {
        alg: 'ES256',
        kid: 'https://ca.example/acme/acct/1',
        nonce: getRandom(16),
        url: 'https://ca.example/acme/other',
      },
      payload: {},
    });
    await expectProblem(
      parseJWS(jws, URL_UNDER_TEST, keyResolver(publicJWK)),
      MALFORMED,
      /url does not match/,
    );
  });

  it('rejects url mismatch on trailing slash alone', async () => {
    const { privateJWK, publicJWK } = await newECKeypair();
    const jws = await signJWS({
      privateJWK,
      protectedHeader: {
        alg: 'ES256',
        kid: 'https://ca.example/acme/acct/1',
        nonce: getRandom(16),
        url: `${URL_UNDER_TEST}/`,
      },
      payload: {},
    });
    await expectProblem(
      parseJWS(jws, URL_UNDER_TEST, keyResolver(publicJWK)),
      MALFORMED,
      /url does not match/,
    );
  });

  it('rejects a tampered signature', async () => {
    const { privateJWK, publicJWK } = await newECKeypair();
    const jws = await signJWS({
      privateJWK,
      protectedHeader: {
        alg: 'ES256',
        kid: 'https://ca.example/acme/acct/1',
        nonce: getRandom(16),
        url: URL_UNDER_TEST,
      },
      payload: {},
    });
    const sigBytes = new Uint8Array(decodeBase64url(jws.signature));
    // Bit-flip keeps ES256's 64-byte length so verify fails on crypto, not on length.
    sigBytes[0] ^= 0x01;
    const tampered: FlattenedJWS = {
      ...jws,
      signature: encodeBase64url(sigBytes),
    };
    await expectProblem(
      parseJWS(tampered, URL_UNDER_TEST, keyResolver(publicJWK)),
      UNAUTHORIZED,
      /signature verification failed/,
    );
  });

  it('rejects a tampered payload', async () => {
    const { privateJWK, publicJWK } = await newECKeypair();
    const jws = await signJWS({
      privateJWK,
      protectedHeader: {
        alg: 'ES256',
        kid: 'https://ca.example/acme/acct/1',
        nonce: getRandom(16),
        url: URL_UNDER_TEST,
      },
      payload: { hello: 'world' },
    });
    const payloadBytes = new Uint8Array(decodeBase64url(jws.payload));
    payloadBytes[0] ^= 0x01;
    const tampered: FlattenedJWS = {
      ...jws,
      payload: encodeBase64url(payloadBytes),
    };
    await expectProblem(
      parseJWS(tampered, URL_UNDER_TEST, keyResolver(publicJWK)),
      UNAUTHORIZED,
      /signature verification failed/,
    );
  });

  it('rejects when verifying with the wrong key', async () => {
    const signer = await newECKeypair();
    const other = await newECKeypair();
    const jws = await signJWS({
      privateJWK: signer.privateJWK,
      protectedHeader: {
        alg: 'ES256',
        kid: 'https://ca.example/acme/acct/1',
        nonce: getRandom(16),
        url: URL_UNDER_TEST,
      },
      payload: {},
    });
    await expectProblem(
      parseJWS(jws, URL_UNDER_TEST, keyResolver(other.publicJWK)),
      UNAUTHORIZED,
      /signature verification failed/,
    );
  });

  it('propagates errors thrown from resolveKey', async () => {
    const { privateJWK } = await newECKeypair();
    const jws = await signJWS({
      privateJWK,
      protectedHeader: {
        alg: 'ES256',
        kid: 'https://ca.example/acme/acct/deactivated',
        nonce: getRandom(16),
        url: URL_UNDER_TEST,
      },
      payload: {},
    });
    const error: unknown = await parseJWS(
      jws, URL_UNDER_TEST, failingResolver,
    ).catch((error_: unknown) => error_);
    expect(error).toBeInstanceOf(Error);
    expect(error).not.toBeInstanceOf(ProblemError);
    expect((error as Error).message).toMatch(/account deactivated/);
  });

  it('passes a ProblemError thrown from resolveKey through unchanged', async () => {
    const { privateJWK } = await newECKeypair();
    const jws = await signJWS({
      privateJWK,
      protectedHeader: {
        alg: 'ES256',
        kid: 'https://ca.example/acme/acct/missing',
        nonce: getRandom(16),
        url: URL_UNDER_TEST,
      },
      payload: {},
    });
    const accountErrorResolver: ResolveKey = async () => {
      throw ProblemError.of(
        ACCOUNT_DOES_NOT_EXIST,
        'no such account',
      );
    };
    const error = await expectProblem(
      parseJWS(jws, URL_UNDER_TEST, accountErrorResolver),
      ACCOUNT_DOES_NOT_EXIST,
      /no such account/,
    );
    // Asserts parseJWS did not re-wrap the resolver's error.
    expect(error.problem.type).toBe(ACCOUNT_DOES_NOT_EXIST);
  });

  it('does not call resolveKey when schema rejects header', async () => {
    let invocations = 0;
    const spy: ResolveKey = async () => {
      invocations += 1;
      throw new Error('resolveKey should not be invoked');
    };
    await expectProblem(
      parseJWS(
        { protected: 'AAAA', payload: '' },
        URL_UNDER_TEST,
        spy,
      ),
      MALFORMED,
      /invalid Flattened JWS/,
    );
    expect(invocations).toBe(0);
  });

  it('rejects a non-JSON payload', async () => {
    const { privateJWK, publicJWK } = await newECKeypair();
    const bytes = new TextEncoder().encode('not-json');
    const signed = await new FlattenedSign(bytes)
      .setProtectedHeader({
        alg: 'ES256',
        kid: 'https://ca.example/acme/acct/1',
        nonce: getRandom(16),
        url: URL_UNDER_TEST,
      })
      .sign(privateJWK);
    const jws = toFlattenedJWS(signed);
    await expectProblem(
      parseJWS(jws, URL_UNDER_TEST, keyResolver(publicJWK)),
      MALFORMED,
      /payload is not valid JSON/,
    );
  });

  it('carries valibot issues on .cause for a structural failure', async () => {
    const { publicJWK } = await newECKeypair();
    const error = await expectProblem(
      parseJWS(
        { protected: 'AAAA', payload: '' },
        URL_UNDER_TEST,
        keyResolver(publicJWK),
      ),
      MALFORMED,
    );
    expect(error.name).toBe('ProblemError');
    expect(Array.isArray(error.cause)).toBe(true);
    expect((error.cause as unknown[]).length).toBeGreaterThan(0);
  });

  it('carries valibot issues on .cause for an unsupported alg', async () => {
    const error = await expectHeaderRejection(
      { alg: 'HS256' },
      BAD_SIGNATURE_ALGORITHM,
    );
    expect(Array.isArray(error.cause)).toBe(true);
    expect((error.cause as unknown[]).length).toBeGreaterThan(0);
  });

  it('attaches { expected, received } on url-mismatch .cause', async () => {
    const { privateJWK, publicJWK } = await newECKeypair();
    const jws = await signJWS({
      privateJWK,
      protectedHeader: {
        alg: 'ES256',
        kid: 'https://ca.example/acme/acct/1',
        nonce: getRandom(16),
        url: 'https://ca.example/acme/other',
      },
      payload: {},
    });
    const error = await expectProblem(
      parseJWS(jws, URL_UNDER_TEST, keyResolver(publicJWK)),
      MALFORMED,
    );
    expect(error.cause).toEqual({
      expected: URL_UNDER_TEST,
      received: 'https://ca.example/acme/other',
    });
  });

  it('carries valibot issues on .cause for a header-schema failure', async () => {
    const { privateJWK, publicJWK } = await newECKeypair();
    const jws = await signJWS({
      privateJWK,
      protectedHeader: { alg: 'ES256' },
      payload: {},
    });
    const error = await expectProblem(
      parseJWS(jws, URL_UNDER_TEST, keyResolver(publicJWK)),
      MALFORMED,
      /invalid ACME protected header/,
    );
    expect(Array.isArray(error.cause)).toBe(true);
    expect((error.cause as unknown[]).length).toBeGreaterThan(0);
  });

  it('carries a SyntaxError on .cause for a non-JSON header', async () => {
    const { privateJWK, publicJWK } = await newECKeypair();
    const jws = await signJWS({
      privateJWK,
      protectedHeader: {
        alg: 'ES256',
        kid: 'https://ca.example/acme/acct/1',
        nonce: getRandom(16),
        url: URL_UNDER_TEST,
      },
      payload: {},
    });
    const tampered: FlattenedJWS = {
      ...jws,
      protected: encodeBase64url(new TextEncoder().encode('{not-json')),
    };
    const error = await expectProblem(
      parseJWS(tampered, URL_UNDER_TEST, keyResolver(publicJWK)),
      MALFORMED,
      /protected header is not valid JSON/,
    );
    expect(error.cause).toBeInstanceOf(SyntaxError);
  });
});
