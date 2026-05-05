// PKCS#10 Certification Request parse + verify
// (RFC 2986, RFC 5280, RFC 8555 §7.4)

import type {
  AuthorityInfoAccess,
  BasicConstraints,
  CSR,
  ExtendedKeyUsage,
  Extension,
  Identifier,
  JWK,
  KeyUsage,
  PEM,
} from '../types';
import { ProblemError, SubproblemError } from '../error';

import { exportJWK } from './jwk';
import { decodePEM } from './pem';
import {
  AuthorityInfoAccessExtension,
  BasicConstraintsExtension,
  CertificatePolicyExtension,
  CRLDistributionPointsExtension,
  ExtendedKeyUsageExtension,
  GeneralName,
  KeyUsageFlags,
  KeyUsagesExtension,
  Pkcs10CertificateRequest,
  SubjectAlternativeNameExtension,
  X509Extension,
} from './x509';

/** RFC 7468 PEM label for a PKCS#10 CSR. */
const CSR_PEM_LABEL = 'CERTIFICATE REQUEST';

/**
 * Bit→name pairs for {@link decodeKeyUsage}, ordered
 * to produce alphabetical output regardless of which
 * bits are set.
 */
const KEY_USAGE_BITS = [
  ['cRLSign', KeyUsageFlags.cRLSign],
  ['dataEncipherment', KeyUsageFlags.dataEncipherment],
  ['decipherOnly', KeyUsageFlags.decipherOnly],
  ['digitalSignature', KeyUsageFlags.digitalSignature],
  ['encipherOnly', KeyUsageFlags.encipherOnly],
  ['keyAgreement', KeyUsageFlags.keyAgreement],
  ['keyCertSign', KeyUsageFlags.keyCertSign],
  ['keyEncipherment', KeyUsageFlags.keyEncipherment],
  ['nonRepudiation', KeyUsageFlags.nonRepudiation],
] as const satisfies readonly (readonly [KeyUsage, number])[];

/**
 * OIDs `parseCSR` decodes into typed slots on the
 * {@link CSR} tree. Extensions whose OID is not in
 * this set fall through to {@link CSR.extensions}.
 */
const TYPED_EXTENSION_OID_SET: ReadonlySet<string> = new Set([
  '2.5.29.17', // SubjectAltName
  '2.5.29.19', // BasicConstraints
  '2.5.29.15', // KeyUsage
  '2.5.29.37', // ExtendedKeyUsage
  '2.5.29.32', // CertificatePolicies
  '2.5.29.31', // CRLDistributionPoints
  '1.3.6.1.5.5.7.1.1', // AuthorityInfoAccess
]);

/**
 * Decode a PEM CSR, verify its proof-of-possession,
 * and return a {@link CSR} tree with every wire-CSR
 * field decoded into typed form.
 *
 * @param pem - armoured CSR carrying the PEM label
 *   `CERTIFICATE REQUEST` (RFC 7468 §8).
 *
 * @remarks
 * Fail-closed at every step. A value returned from
 * this function is PoP-verified by construction —
 * callers need not re-check the self-signature.
 *
 * 1. The PEM label must be `CERTIFICATE REQUEST`
 *    (decoder rejects any other tag).
 * 2. The CSR's self-signature must verify against its
 *    declared `subjectPublicKey`
 *    (`@peculiar/x509.verify()` via WebCrypto).
 * 3. Each SAN entry in the `extensionRequest`
 *    attribute must be a `dns` or `ip` name — ACME's
 *    admissible identifier types (RFC 8555 §7.1.4,
 *    RFC 8738). `email`, `URI`, `otherName`, etc.
 *    cause rejection.
 *
 * The CSR's `extensionRequest` attribute is decoded
 * into typed slots where the OID is recognised
 * (`basicConstraints`, `keyUsage`, `extendedKeyUsage`,
 * `certificatePolicies`, `authorityInfoAccess`,
 * `crlDistributionPoints`). Anything else is
 * preserved on `extensions` as an envelope carrying
 * the dotted OID `id`, the optional RFC 5280 §4.2
 * `critical` bit, and the raw DER `value`, so the
 * orchestrator can filter or pass-through with the
 * OID intact.
 *
 * Orchestrator-only TBS slots (`issuer`, `notBefore`,
 * `notAfter`) stay `undefined` — the orchestrator
 * fills them from CA policy before handing the tree
 * to `signer.issue(csr)`.
 *
 * `subjectPublicKey` goes through {@link exportJWK} so
 * its coordinate/modulus members carry the `Base64url`
 * brand. `der` preserves the original wire bytes for
 * pass-through to CT log submissions and audit trails.
 *
 * @throws {@link ProblemError} mapped to the ACME error
 *   URN that best fits the failure mode:
 *   - `malformed` — PEM armour broken, wrong label,
 *     or DER the x509 parser cannot decode.
 *   - `badCSR` — PoP verification failed, or
 *     `@peculiar/x509`'s `verify()` raised (e.g.
 *     unsupported signature algorithm).
 *   - `badPublicKey` — the subject public key cannot
 *     be exported to a JWK (unsupported curve,
 *     malformed key material, etc.).
 *   - `compound` carrying one
 *     `unsupportedIdentifier` Subproblem per
 *     non-ACME SAN entry (`email`, `URI`,
 *     `otherName`, …) — see
 *     {@link extractSANIdentifiers}.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc2986}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc5280}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.4}
 */
export async function parseCSR(pem: PEM): Promise<CSR> {
  const der = decodePEM(pem, CSR_PEM_LABEL);

  let csr: Pkcs10CertificateRequest;
  try {
    csr = new Pkcs10CertificateRequest(der);
  } catch (error) {
    throw ProblemError.malformed(
      'CSR DER bytes failed to parse',
      { cause: error },
    );
  }

  let ok: boolean;
  try {
    ok = await csr.verify();
  } catch (error) {
    throw ProblemError.of(
      'urn:ietf:params:acme:error:badCSR',
      'CSR proof-of-possession signature could not be verified',
      { cause: error },
    );
  }
  if (!ok) {
    throw ProblemError.of(
      'urn:ietf:params:acme:error:badCSR',
      'CSR proof-of-possession signature failed to verify',
    );
  }

  let subjectPublicKey: JWK;
  try {
    const cryptoKey = await csr.publicKey.export();
    subjectPublicKey = await exportJWK(cryptoKey);
  } catch (error) {
    throw ProblemError.of(
      'urn:ietf:params:acme:error:badPublicKey',
      'CSR subject public key could not be exported as a JWK',
      { cause: error },
    );
  }

  const out: CSR = {
    der,
    subject: csr.subjectName.toJSON(),
    subjectPublicKey,
    sans: extractSANIdentifiers(csr.extensions),
  };

  setIfPresent(out, 'basicConstraints', extractBasicConstraints(csr.extensions));
  setIfPresent(out, 'keyUsage', extractKeyUsage(csr.extensions));
  setIfPresent(out, 'extendedKeyUsage', extractExtendedKeyUsage(csr.extensions));
  setIfPresent(out, 'certificatePolicies', extractCertificatePolicies(csr.extensions));
  setIfPresent(out, 'authorityInfoAccess', extractAuthorityInfoAccess(csr.extensions));
  setIfPresent(out, 'crlDistributionPoints', extractCRLDistributionPoints(csr.extensions));
  setIfPresent(out, 'extensions', extractRemainingExtensions(csr.extensions));

  return out;
}

/**
 * Assign `value` to `target[key]` only when `value` is
 * defined. Keeps the extractor pipeline shape
 * `setIfPresent(out, 'k', extract(...))` without leaking
 * `undefined` onto the result — `'k' in out` stays
 * `false` when the source CSR carried no extension of
 * that type.
 */
function setIfPresent<O extends object, K extends keyof O>(
  target: O,
  key: K,
  value: O[K] | undefined,
): void {
  if (value !== undefined) target[key] = value;
}

/**
 * Find the first extension whose runtime class is
 * `extensionClass`, narrowed to that subclass.
 *
 * @typeParam T - peculiar extension subclass to narrow
 *   to
 * @param extensions - extensions list (any collection
 *   parsed through `@peculiar/x509`'s
 *   `ExtensionFactory`: CSR `extensionRequest`,
 *   `X509Certificate.extensions`,
 *   `X509Crl.extensions`)
 * @param extensionClass - constructor of the desired
 *   subclass
 * @returns the first matching extension, or
 *   `undefined`
 *
 * @remarks
 * `@peculiar/x509`'s `ExtensionFactory` instantiates
 * the OID-specific subclass during parse, so an
 * `instanceof` probe is enough — no OID match by
 * string. Subclass-specific extractors
 * ({@link extractBasicConstraints},
 * {@link extractKeyUsage}, …) compose this helper.
 */
export function findExtension<T extends X509Extension>(
  extensions: readonly X509Extension[],
  extensionClass: new (...arguments_: never[]) => T,
): T | undefined {
  return extensions.find(
    (candidate): candidate is T =>
      candidate instanceof extensionClass,
  );
}

/**
 * Find the first extension whose ASN.1 OID matches
 * `oid`, untyped.
 *
 * @param extensions - extensions list (any collection
 *   parsed through `@peculiar/x509`'s
 *   `ExtensionFactory`)
 * @param oid - dotted ASN.1 OID
 * @returns the first matching extension, or
 *   `undefined`
 *
 * @remarks
 * Companion to {@link findExtension} for OIDs that
 * `@peculiar/x509` does not model with a typed
 * subclass — callers get the generic `X509Extension`
 * back and must read the raw DER `value` themselves.
 * Use {@link findExtension} whenever a typed subclass
 * exists.
 */
export function findExtensionByType(
  extensions: readonly X509Extension[],
  oid: string,
): undefined | X509Extension {
  return extensions.find(
    (candidate) => candidate.type === oid,
  );
}

/**
 * Find the Subject Alternative Name extension in an
 * extensions list.
 *
 * @returns The `SubjectAlternativeNameExtension`, or
 *   `undefined` if the list has no SAN entry.
 *
 * @remarks
 * Wrapper over {@link findExtension} pinned to the SAN
 * subclass — kept as a named export because
 * {@link extractSANIdentifiers} works with the typed
 * subclass directly rather than projecting to a
 * plain-data shape.
 */
export function findSANExtension(
  extensions: readonly X509Extension[],
): SubjectAlternativeNameExtension | undefined {
  return findExtension(extensions, SubjectAlternativeNameExtension);
}

/**
 * Extract SAN entries as ACME {@link Identifier}s.
 *
 * @param extensions - extensions list (CSR
 *   `extensionRequest` items,
 *   `X509Certificate.extensions`, or any collection
 *   parsed through `@peculiar/x509`'s
 *   `ExtensionFactory`).
 *
 * @returns An array of ACME identifiers — empty when
 *   no SAN extension is present.
 *
 * @remarks
 * Restricted to the ACME-admissible SAN types `dns`
 * (RFC 8555 §7.1.4) and `ip` (RFC 8738). Entries of
 * other types (`email`, `URI`, `otherName`, …) are
 * collected as `unsupportedIdentifier` Subproblems
 * and rolled into a single `compound` ProblemError
 * — every bad SAN appears in `subproblems`, not just
 * the first. The Subproblem omits `identifier`
 * because the ACME `Identifier` type only models
 * `dns` / `ip`; the offending SAN type and value
 * appear in `detail` instead.
 *
 * Multiplicity is preserved as it appears in the CSR
 * — duplicate SANs come back duplicated, original
 * order is kept. Deduplication, IPv6 canonicalisation,
 * and DNS case folding are deliberately not the
 * extractor's concern; consumers (ACME order
 * matching, storage keys, comparison paths) decide
 * their own normalisation policy.
 *
 * @throws {@link ProblemError} of type `compound`
 *   carrying one `unsupportedIdentifier` Subproblem
 *   per non-ACME SAN entry, when at least one such
 *   entry is present.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.4}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8738}
 */
export function extractSANIdentifiers(
  extensions: readonly X509Extension[],
): Identifier[] {
  const san = findSANExtension(extensions);
  if (!san) {
    return [];
  }
  const accepted: Identifier[] = [];
  const rejected: SubproblemError[] = [];
  for (const gn of san.names.toJSON()) {
    switch (gn.type) {
      case 'dns':
        accepted.push({ type: 'dns', value: gn.value });
        break;
      case 'ip':
        accepted.push({ type: 'ip', value: gn.value });
        break;
      default:
        rejected.push(SubproblemError.of(
          'urn:ietf:params:acme:error:unsupportedIdentifier',
          undefined,
          `non-ACME SAN type '${gn.type}': ${gn.value}`,
        ));
    }
  }
  if (rejected.length > 0) {
    throw ProblemError.compound(
      rejected,
      'CSR contains SAN entries of unsupported type',
    );
  }
  return accepted;
}

/**
 * Decode a `KeyUsageFlags` bitmask into the
 * alphabetically-sorted {@link KeyUsage} string array.
 */
function decodeKeyUsage(flags: number): KeyUsage[] {
  const out: KeyUsage[] = [];
  for (const [name, bit] of KEY_USAGE_BITS) {
    if ((flags & bit) !== 0) out.push(name);
  }
  return out;
}

/** Pull URI general names from a list of {@link GeneralName}s. */
function generalNamesToURIs(
  names: readonly GeneralName[],
): string[] {
  const uris: string[] = [];
  for (const name of names) {
    const json = name.toJSON();
    if (json.type === 'url') uris.push(json.value);
  }
  return uris;
}

/**
 * Extract {@link BasicConstraints} from an extensions
 * list, or `undefined` if the extension is absent.
 */
export function extractBasicConstraints(
  extensions: readonly X509Extension[],
): BasicConstraints | undefined {
  const extension = findExtension(extensions, BasicConstraintsExtension);
  if (!extension) return undefined;
  return extension.pathLength === undefined ?
    { ca: extension.ca } :
    { ca: extension.ca, pathLength: extension.pathLength };
}

/**
 * Extract {@link KeyUsage} names from an extensions
 * list, or `undefined` if the extension is absent.
 */
export function extractKeyUsage(
  extensions: readonly X509Extension[],
): KeyUsage[] | undefined {
  const extension = findExtension(extensions, KeyUsagesExtension);
  if (!extension) return undefined;
  return decodeKeyUsage(extension.usages);
}

/**
 * Extract {@link ExtendedKeyUsage} purposes from an
 * extensions list, or `undefined` if the extension is
 * absent.
 */
export function extractExtendedKeyUsage(
  extensions: readonly X509Extension[],
): ExtendedKeyUsage[] | undefined {
  const extension = findExtension(extensions, ExtendedKeyUsageExtension);
  if (!extension) return undefined;
  // peculiar types `usages` as `ExtendedKeyUsageType[]`
  // (asn1 enum | string); the runtime form is always a
  // dotted-OID string, so coerce.
  return extension.usages.map(String);
}

/**
 * Extract certificate-policy OIDs from an extensions
 * list, or `undefined` if the extension is absent.
 */
export function extractCertificatePolicies(
  extensions: readonly X509Extension[],
): string[] | undefined {
  const extension = findExtension(extensions, CertificatePolicyExtension);
  if (!extension) return undefined;
  return [...extension.policies];
}

/**
 * Extract {@link AuthorityInfoAccess} from an
 * extensions list, or `undefined` if the extension is
 * absent or carries no URI access entries.
 *
 * @remarks
 * Only `uniformResourceIdentifier` general names are
 * surfaced; non-URI forms (DN, otherName) and the
 * less common `timeStamping` / `caRepository` access
 * methods fall through silently. The orchestrator can
 * pull anything it wants from the raw `extensions`
 * envelope (see {@link CSR.extensions}) if a
 * deployment cares.
 */
export function extractAuthorityInfoAccess(
  extensions: readonly X509Extension[],
): AuthorityInfoAccess | undefined {
  const extension = findExtension(extensions, AuthorityInfoAccessExtension);
  if (!extension) return undefined;
  const caIssuers = generalNamesToURIs(extension.caIssuers);
  const ocsp = generalNamesToURIs(extension.ocsp);
  const out: AuthorityInfoAccess = {};
  if (caIssuers.length > 0) out.caIssuers = caIssuers;
  if (ocsp.length > 0) out.ocsp = ocsp;
  return Object.keys(out).length > 0 ? out : undefined;
}

/**
 * Extract CRL distribution-point URIs from an
 * extensions list, or `undefined` if the extension is
 * absent or carries no URI entries.
 *
 * @remarks
 * Walks each `DistributionPoint`'s `fullName` for
 * `uniformResourceIdentifier` general names and
 * concatenates them. Non-URI distribution-point
 * forms (`nameRelativeToCRLIssuer`, DN-form
 * `fullName` entries) are not modelled and fall
 * through silently — the typical wire form is
 * URI-only.
 */
export function extractCRLDistributionPoints(
  extensions: readonly X509Extension[],
): string[] | undefined {
  const extension = findExtension(extensions, CRLDistributionPointsExtension);
  if (!extension) return undefined;
  const uris: string[] = [];
  for (const dp of extension.distributionPoints) {
    const fullName = dp.distributionPoint?.fullName;
    if (!fullName) continue;
    for (const asn of fullName) {
      const { type, value } = new GeneralName(asn).toJSON();
      if (type === 'url') uris.push(value);
    }
  }
  return uris.length > 0 ? uris : undefined;
}

/**
 * Project extensions whose OID has no typed slot on
 * the {@link CSR} tree into the serialisable
 * {@link Extension} shape, preserving OID, critical
 * bit, and DER `extnValue`. Returns `undefined` when
 * no such extension is present.
 *
 * @remarks
 * The set of OIDs that get typed slots is fixed at
 * the {@link CSR} shape level — adding a new typed
 * slot must extend `TYPED_EXTENSION_OID_SET` so the same
 * extension does not appear twice (once decoded, once
 * raw). Order is preserved as it appears in the
 * source list.
 */
export function extractRemainingExtensions(
  extensions: readonly X509Extension[],
): Extension[] | undefined {
  const remaining: Extension[] = [];
  for (const extension of extensions) {
    if (TYPED_EXTENSION_OID_SET.has(extension.type)) continue;
    const entry: Extension = {
      id: extension.type,
      value: new Uint8Array(extension.value),
    };
    if (extension.critical) entry.critical = true;
    remaining.push(entry);
  }
  return remaining.length > 0 ? remaining : undefined;
}
