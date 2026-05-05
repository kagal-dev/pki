// End-to-end proof: a parsed CSR tree, amended by an
// orchestrator stand-in, can be assembled into a real
// X.509 certificate that verifies under the issuing CA's
// public key. Validates the CSR tree shape against
// what a future `signer.issue(csr)` will need.
//
// The signer itself lives in `@kagal/ca`. The helper here
// is a deliberate stand-in — the real signer adds atomic
// serial allocation, CT, secure-log, KEK lifecycle, etc.
// The point of this test is to exercise the data path,
// not the side-effect path.

import { describe, expect, it } from 'vitest';

import {
  type AuthorityInfoAccess,
  type BasicConstraints,
  type CSR,
  type DistinguishedName,
  type ExtendedKeyUsage,
  type Extension,
  type Identifier,
  type KeyUsage,
} from '../../types';
import { asPEM } from '../../types';
import { findExtensionByType, parseCSR } from '../csr';
import {
  AuthorityInfoAccessExtension,
  BasicConstraintsExtension,
  CertificatePolicyExtension,
  CRLDistributionPointsExtension,
  ExtendedKeyUsageExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  Pkcs10CertificateRequestGenerator,
  SubjectAlternativeNameExtension,
  X509Certificate,
  X509CertificateGenerator,
  X509Extension,
} from '../x509';

const ECDSA_P256 = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const ECDSA_SIGN = { name: 'ECDSA', hash: 'SHA-256' } as const;
const ED25519 = { name: 'Ed25519' } as const;
const RSA_2048 = {
  hash: 'SHA-256',
  modulusLength: 2048,
  name: 'RSASSA-PKCS1-v1_5',
  publicExponent: new Uint8Array([1, 0, 1]),
} as const;
const RSA_IMPORT = { hash: 'SHA-256', name: 'RSASSA-PKCS1-v1_5' } as const;

/**
 * Leaf algorithm matrix for the round-trip path —
 * generates the CSR keypair, drives parseCSR, and feeds
 * {@link publicKeyFromCSR} via the `kty` / `crv`
 * dispatch. The issuing CA stays ECDSA P-256
 * regardless; only the leaf SPKI varies.
 */
const LEAF_ALGORITHMS = [
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

/**
 * Bit→name pairs mirroring the production table in
 * `utils/csr.ts` — `KEY_USAGE_BITS` there is private,
 * so the round-trip helper carries its own copy. The
 * `Record` shape gives exhaustiveness against
 * {@link KeyUsage}.
 */
const KEY_USAGE_BITS: Readonly<Record<KeyUsage, number>> = {
  cRLSign: KeyUsageFlags.cRLSign,
  dataEncipherment: KeyUsageFlags.dataEncipherment,
  decipherOnly: KeyUsageFlags.decipherOnly,
  digitalSignature: KeyUsageFlags.digitalSignature,
  encipherOnly: KeyUsageFlags.encipherOnly,
  keyAgreement: KeyUsageFlags.keyAgreement,
  keyCertSign: KeyUsageFlags.keyCertSign,
  keyEncipherment: KeyUsageFlags.keyEncipherment,
  nonRepudiation: KeyUsageFlags.nonRepudiation,
};

/**
 * Map our {@link KeyUsage} string array to peculiar's
 * `KeyUsageFlags` bitmask.
 */
function keyUsageToFlags(usages: readonly KeyUsage[]): number {
  let flags = 0;
  for (const usage of usages) {
    flags |= KEY_USAGE_BITS[usage];
  }
  return flags;
}

/**
 * Build a peculiar `X509Extension` list from a {@link CSR}
 * tree's typed slots plus its raw `extensions` envelope.
 */
function extensionsFromCSR(csr: CSR): X509Extension[] {
  const out: X509Extension[] = [];
  if (csr.sans.length > 0) {
    out.push(new SubjectAlternativeNameExtension(
      csr.sans.map((s) => ({ type: s.type, value: s.value })),
    ));
  }
  if (csr.basicConstraints) {
    out.push(new BasicConstraintsExtension(
      csr.basicConstraints.ca,
      csr.basicConstraints.pathLength,
    ));
  }
  if (csr.keyUsage) {
    out.push(new KeyUsagesExtension(keyUsageToFlags(csr.keyUsage)));
  }
  if (csr.extendedKeyUsage) {
    out.push(new ExtendedKeyUsageExtension([...csr.extendedKeyUsage]));
  }
  if (csr.certificatePolicies) {
    out.push(new CertificatePolicyExtension([...csr.certificatePolicies]));
  }
  if (csr.authorityInfoAccess) {
    out.push(new AuthorityInfoAccessExtension({
      caIssuers: csr.authorityInfoAccess.caIssuers,
      ocsp: csr.authorityInfoAccess.ocsp,
    }));
  }
  if (csr.crlDistributionPoints) {
    out.push(new CRLDistributionPointsExtension(
      [...csr.crlDistributionPoints],
    ));
  }
  for (const extension of csr.extensions ?? []) {
    // Force an ArrayBuffer-backed copy so `BufferSource`
    // narrows past the SharedArrayBuffer overload TS sees.
    out.push(new X509Extension(
      extension.id, extension.critical ?? false, new Uint8Array(extension.value),
    ));
  }
  return out;
}

/**
 * Convert an {@link CSR.subjectPublicKey} JWK back to a
 * WebCrypto `CryptoKey` for the cert's SPKI slot.
 *
 * @remarks
 * Dispatches on `kty` / `crv` for the algorithms the
 * production `parseCSR` / `exportJWK` chain reaches via
 * jose: ECDSA P-256, Ed25519, and RSASSA-PKCS1-v1_5 with
 * SHA-256.
 */
async function publicKeyFromCSR(csr: CSR): Promise<CryptoKey> {
  const jwk = csr.subjectPublicKey;
  if (jwk.kty === 'EC' && jwk.crv === 'P-256') {
    return crypto.subtle.importKey('jwk', jwk, ECDSA_P256, true, []);
  }
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
    return crypto.subtle.importKey('jwk', jwk, ED25519, true, []);
  }
  if (jwk.kty === 'RSA') {
    return crypto.subtle.importKey('jwk', jwk, RSA_IMPORT, true, []);
  }
  // After the three kty/crv branches, only EC{P-384,
  // P-521} and OKP{Ed448, X25519, X448} remain — both
  // shapes carry crv.
  throw new Error(
    `round-trip helper does not handle ${jwk.kty}/${jwk.crv}`,
  );
}

/**
 * Stand-in for `signer.issue(csr)` — assemble a cert from
 * a fully amended {@link CSR} tree. Returns the peculiar
 * `X509Certificate` so the caller can both PEM-export
 * and `verify()` against the issuer's public key.
 */
async function signCertificateFromCSR(arguments_: {
  csr: CSR
  serialNumber: string
  signingKey: CryptoKey
}): Promise<X509Certificate> {
  const { csr, signingKey, serialNumber } = arguments_;
  if (!csr.issuer || !csr.notBefore || !csr.notAfter) {
    throw new Error(
      'CSR tree must have issuer, notBefore, notAfter set before signing',
    );
  }
  const publicKey = await publicKeyFromCSR(csr);
  return X509CertificateGenerator.create({
    serialNumber,
    subject: csr.subject,
    issuer: csr.issuer,
    notBefore: csr.notBefore,
    notAfter: csr.notAfter,
    publicKey,
    signingKey,
    signingAlgorithm: ECDSA_SIGN,
    extensions: extensionsFromCSR(csr),
  });
}

/** Stand-in for the orchestrator's amend pass on a parsed CSR. */
function amendCSR(
  csr: CSR,
  amendments: {
    authorityInfoAccess?: AuthorityInfoAccess
    basicConstraints?: BasicConstraints
    certificatePolicies?: string[]
    crlDistributionPoints?: string[]
    extendedKeyUsage?: ExtendedKeyUsage[]
    extensions?: Extension[]
    issuer: DistinguishedName
    keyUsage?: KeyUsage[]
    notAfter: Date
    notBefore: Date
    sans?: Identifier[]
  },
): CSR {
  const out: CSR = {
    ...csr,
    issuer: amendments.issuer,
    notBefore: amendments.notBefore,
    notAfter: amendments.notAfter,
  };
  if (amendments.sans) out.sans = amendments.sans;
  if (amendments.basicConstraints) {
    out.basicConstraints = amendments.basicConstraints;
  }
  if (amendments.keyUsage) out.keyUsage = amendments.keyUsage;
  if (amendments.extendedKeyUsage) {
    out.extendedKeyUsage = amendments.extendedKeyUsage;
  }
  if (amendments.certificatePolicies) {
    out.certificatePolicies = amendments.certificatePolicies;
  }
  if (amendments.authorityInfoAccess) {
    out.authorityInfoAccess = amendments.authorityInfoAccess;
  }
  if (amendments.crlDistributionPoints) {
    out.crlDistributionPoints = amendments.crlDistributionPoints;
  }
  if (amendments.extensions) out.extensions = amendments.extensions;
  return out;
}

async function newLeafCSR(
  sans: Identifier[],
  alg: typeof LEAF_ALGORITHMS[number] = LEAF_ALGORITHMS[0],
): Promise<{
  keys: CryptoKeyPair
  pem: string
}> {
  // generateKey returns `CryptoKey | CryptoKeyPair`
  // because the algorithm union spans symmetric and
  // asymmetric forms; every entry in `LEAF_ALGORITHMS`
  // is asymmetric, so the cast is sound.
  const keys = (await crypto.subtle.generateKey(
    alg.keygen, true, ['sign', 'verify'],
  )) as CryptoKeyPair;
  const csr = await Pkcs10CertificateRequestGenerator.create({
    name: '',
    keys,
    signingAlgorithm: alg.sign,
    extensions: [
      new SubjectAlternativeNameExtension(
        sans.map((s) => ({ type: s.type, value: s.value })),
      ),
    ],
  });
  return { pem: csr.toString('pem'), keys };
}

async function newRootCert(): Promise<{
  cert: X509Certificate
  keys: CryptoKeyPair
}> {
  const keys = await crypto.subtle.generateKey(
    ECDSA_P256, true, ['sign', 'verify'],
  );
  const cert = await X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: [{ CN: ['Round-Trip Test Root CA'] }, { O: ['kagal'] }],
    notBefore: new Date('2026-01-01T00:00:00Z'),
    notAfter: new Date('2036-01-01T00:00:00Z'),
    keys,
    signingAlgorithm: ECDSA_SIGN,
    extensions: [
      new BasicConstraintsExtension(true, 1),
      new KeyUsagesExtension(
        KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign,
      ),
    ],
  });
  return { cert, keys };
}

describe('CSR tree → signed cert round-trip', () => {
  it('amends a parsed CSR and signs a verifiable leaf', async () => {
    const root = await newRootCert();
    const { pem } = await newLeafCSR([
      { type: 'dns', value: 'leaf.example.com' },
      { type: 'dns', value: 'www.leaf.example.com' },
    ]);
    const parsed = await parseCSR(asPEM(pem));

    // Wire-CSR fields the parser populated.
    expect(parsed.sans).toEqual([
      { type: 'dns', value: 'leaf.example.com' },
      { type: 'dns', value: 'www.leaf.example.com' },
    ]);
    expect(parsed.subjectPublicKey.kty).toBe('EC');
    // Orchestrator-only slots start undefined.
    expect(parsed.issuer).toBeUndefined();
    expect(parsed.notBefore).toBeUndefined();
    expect(parsed.notAfter).toBeUndefined();

    // Custom DER for an opaque OID — proves
    // `extensions[]` round-trips intact through the
    // typed slot machinery.
    const customOID = '1.3.6.1.4.1.99999.1';
    const customDER = new Uint8Array([
      // OCTET STRING { "kagal" }
      0x04, 0x05, 0x6B, 0x61, 0x67, 0x61, 0x6C,
    ]);

    const amended = amendCSR(parsed, {
      issuer: root.cert.subjectName.toJSON(),
      notBefore: new Date('2026-05-01T00:00:00Z'),
      notAfter: new Date('2026-08-01T00:00:00Z'),
      basicConstraints: { ca: false },
      keyUsage: ['digitalSignature', 'keyEncipherment'],
      extendedKeyUsage: ['1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2'],
      certificatePolicies: ['2.5.29.32.0'],
      authorityInfoAccess: {
        caIssuers: ['http://ca.example.com/root.cer'],
        ocsp: ['http://ocsp.example.com/'],
      },
      crlDistributionPoints: ['http://crl.example.com/root.crl'],
      extensions: [{ id: customOID, value: customDER }],
    });

    const cert = await signCertificateFromCSR({
      csr: amended,
      signingKey: root.keys.privateKey,
      serialNumber: '02',
    });

    // Chain check: leaf signature verifies under root.
    expect(await cert.verify({
      publicKey: root.cert.publicKey,
    })).toBe(true);

    // Issuer / subject / validity propagated correctly.
    expect(cert.issuerName.toJSON()).toEqual(
      root.cert.subjectName.toJSON(),
    );
    expect(cert.notBefore.toISOString())
      .toBe('2026-05-01T00:00:00.000Z');
    expect(cert.notAfter.toISOString())
      .toBe('2026-08-01T00:00:00.000Z');
    expect(cert.serialNumber).toBe('02');

    // Re-parse the issued cert as a CSR-like tree so we
    // can assert each amended slot landed in the wire
    // form.
    const reparsedSANs = cert.getExtension(SubjectAlternativeNameExtension);
    expect(reparsedSANs?.names.toJSON()).toEqual([
      { type: 'dns', value: 'leaf.example.com' },
      { type: 'dns', value: 'www.leaf.example.com' },
    ]);

    const bc = cert.getExtension(BasicConstraintsExtension);
    expect(bc?.ca).toBe(false);

    const ku = cert.getExtension(KeyUsagesExtension);
    expect(ku?.usages).toBe(
      KeyUsageFlags.digitalSignature | KeyUsageFlags.keyEncipherment,
    );

    const eku = cert.getExtension(ExtendedKeyUsageExtension);
    expect(eku?.usages).toEqual([
      '1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2',
    ]);

    const policies = cert.getExtension(CertificatePolicyExtension);
    expect(policies?.policies).toEqual(['2.5.29.32.0']);

    const aia = cert.getExtension(AuthorityInfoAccessExtension);
    expect(aia?.ocsp.map((g) => g.toJSON()))
      .toEqual([{ type: 'url', value: 'http://ocsp.example.com/' }]);
    expect(aia?.caIssuers.map((g) => g.toJSON()))
      .toEqual([{ type: 'url', value: 'http://ca.example.com/root.cer' }]);

    const custom = findExtensionByType(cert.extensions, customOID);
    expect(custom).toBeDefined();
    expect(new Uint8Array(custom!.value)).toEqual(customDER);
  });

  it('preserves CSR-supplied typed extensions through reparse', async () => {
    // Generate a CSR carrying typed extensions client-side
    // (BasicConstraints, KeyUsage, ExtendedKeyUsage).
    // parseCSR must surface them on the typed slots, and
    // our extensions list builder must round-trip them
    // back into the issued cert.
    const keys = await crypto.subtle.generateKey(
      ECDSA_P256, true, ['sign', 'verify'],
    );
    const csr = await Pkcs10CertificateRequestGenerator.create({
      name: '',
      keys,
      signingAlgorithm: ECDSA_SIGN,
      extensions: [
        new SubjectAlternativeNameExtension([
          { type: 'dns', value: 'leaf.example.com' },
        ]),
        new BasicConstraintsExtension(false),
        new KeyUsagesExtension(
          KeyUsageFlags.digitalSignature | KeyUsageFlags.keyAgreement,
        ),
        new ExtendedKeyUsageExtension(['1.3.6.1.5.5.7.3.1']),
      ],
    });
    const parsed = await parseCSR(asPEM(csr.toString('pem')));

    expect(parsed.basicConstraints).toEqual({ ca: false });
    // Decoded into alphabetical order.
    expect(parsed.keyUsage).toEqual(['digitalSignature', 'keyAgreement']);
    expect(parsed.extendedKeyUsage).toEqual(['1.3.6.1.5.5.7.3.1']);

    const root = await newRootCert();
    const amended = amendCSR(parsed, {
      issuer: root.cert.subjectName.toJSON(),
      notBefore: new Date('2026-05-01T00:00:00Z'),
      notAfter: new Date('2026-08-01T00:00:00Z'),
    });
    const cert = await signCertificateFromCSR({
      csr: amended,
      signingKey: root.keys.privateKey,
      serialNumber: '03',
    });

    expect(await cert.verify({
      publicKey: root.cert.publicKey,
    })).toBe(true);

    const ku = cert.getExtension(KeyUsagesExtension);
    expect(ku?.usages).toBe(
      KeyUsageFlags.digitalSignature | KeyUsageFlags.keyAgreement,
    );
    const eku = cert.getExtension(ExtendedKeyUsageExtension);
    expect(eku?.usages).toEqual(['1.3.6.1.5.5.7.3.1']);
  });

  it.each(LEAF_ALGORITHMS)(
    'round-trips a $label leaf through the signer stand-in',
    async (alg) => {
      const root = await newRootCert();
      const { pem } = await newLeafCSR(
        [{ type: 'dns', value: 'leaf.example.com' }],
        alg,
      );
      const parsed = await parseCSR(asPEM(pem));
      expect(parsed.subjectPublicKey.kty).toBe(alg.expectedKty);

      const amended = amendCSR(parsed, {
        issuer: root.cert.subjectName.toJSON(),
        notBefore: new Date('2026-05-01T00:00:00Z'),
        notAfter: new Date('2026-08-01T00:00:00Z'),
      });
      const cert = await signCertificateFromCSR({
        csr: amended,
        signingKey: root.keys.privateKey,
        serialNumber: '04',
      });
      expect(await cert.verify({
        publicKey: root.cert.publicKey,
      })).toBe(true);
    },
  );
});
