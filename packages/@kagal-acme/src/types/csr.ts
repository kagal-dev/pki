// PKCS#10 Certification Request (RFC 2986, RFC 8555 §7.4)
// + RFC 5280 TBS slots the orchestrator amends before
// the signer assembles the certificate.

import type { JWK } from './jws/jwk';
import type { Identifier } from './objects/identifier';

/**
 * RFC 5280 Distinguished Name — a sequence of Relative
 * Distinguished Names (RDNs). Each RDN maps attribute
 * short-names (`CN`, `O`, `OU`, `C`, …) to one or more
 * string values.
 *
 * @remarks
 * Plain-data shape, runtime-dep-free. Structurally
 * compatible with `@peculiar/x509`'s `JsonName`
 * (`Array<Record<string, string[]>>`) so
 * `@kagal/acme/utils` can convert without re-encoding.
 *
 * ACME CSRs typically carry an empty subject — the
 * SANs in the `extensionRequest` attribute are
 * authoritative (RFC 8555 §7.4, CA/Browser Forum BR
 * §7.1.4.2).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4}
 */
export type DistinguishedName = Record<string, string[]>[];

/**
 * RFC 5280 §4.2.1.3 KeyUsage bit names.
 *
 * @remarks
 * Modelled as a string array (rather than the wire
 * bit-flag form) so orchestrator filter / amend
 * passes work with straightforward array operations.
 */
export type KeyUsage =
  | 'cRLSign' |
  'dataEncipherment' |
  'decipherOnly' |
  'digitalSignature' |
  'encipherOnly' |
  'keyAgreement' |
  'keyCertSign' |
  'keyEncipherment' |
  'nonRepudiation';

/**
 * RFC 5280 §4.2.1.12 ExtendedKeyUsage purpose.
 *
 * @remarks
 * Either an OID dotted string (`'1.3.6.1.5.5.7.3.1'`)
 * or a short name from `@peculiar/x509`'s
 * `ExtendedKeyUsage` enum (`'serverAuth'`,
 * `'clientAuth'`, `'codeSigning'`,
 * `'emailProtection'`, `'timeStamping'`,
 * `'ocspSigning'`).
 */
export type ExtendedKeyUsage = string;

/**
 * RFC 5280 §4.2.1.9 BasicConstraints.
 */
export type BasicConstraints = {
  /** Whether this certificate may sign other certs. */
  ca: boolean

  /**
   * Maximum non-self-issued intermediates that may
   * follow this certificate in a valid chain.
   * Meaningful only when `ca` is `true`.
   */
  pathLength?: number
};

/**
 * RFC 5280 §4.2.2.1 AuthorityInfoAccess — the URLs a
 * relying party uses to fetch the issuer chain
 * (`caIssuers`) and OCSP responses (`ocsp`).
 *
 * @remarks
 * `parseCSR` populates entries it can decode from
 * `uniformResourceIdentifier` general names. Other
 * AIA access methods (`timeStamping`, `caRepository`,
 * non-URI general names) fall through to
 * {@link CSR.extensions} and the orchestrator
 * decides what to keep.
 */
export type AuthorityInfoAccess = {
  /** CA Issuer (parent cert / chain) URLs. */
  caIssuers?: string[]

  /** OCSP responder URLs. */
  ocsp?: string[]
};

/**
 * Generic extension envelope for OIDs the {@link CSR}
 * shape doesn't model first-class.
 *
 * @remarks
 * Carries the ASN.1 OID and DER `extnValue` so the
 * round-trip is lossless. Used both for wire-CSR
 * extensions outside the typed slots (e.g. legacy
 * Microsoft attributes a client embeds) and for
 * orchestrator-added deployment-specific extensions
 * (hand-encoded via `@peculiar/asn1-schema` or any
 * other ASN.1 toolkit). The signer copies entries
 * verbatim into the certificate's extension list.
 */
export type Extension = {
  /** Dotted ASN.1 OID. */
  id: string

  /** RFC 5280 §4.2 critical bit. Defaults to `false`. */
  critical?: boolean

  /** DER-encoded `extnValue`. */
  value: Uint8Array
};

/**
 * Decoded PKCS#10 Certification Request, expanded
 * with the RFC 5280 TBS slots the orchestrator
 * amends before the signer assembles the
 * certificate.
 *
 * @remarks
 * Two writers share the shape:
 *
 * - `parseCSR` (in `@kagal/acme/utils`) populates
 *   wire-CSR-derived fields (`der`, `subject`,
 *   `subjectPublicKey`, `sans`) and any typed
 *   extensions present in the CSR's
 *   `extensionRequest` (`basicConstraints`,
 *   `keyUsage`, `extendedKeyUsage`,
 *   `certificatePolicies`, `authorityInfoAccess`,
 *   `crlDistributionPoints`). Extensions whose OID
 *   has no typed slot land in `extensions`.
 *   Orchestrator-only fields (`issuer`, `notBefore`,
 *   `notAfter`) stay `undefined`.
 * - The orchestrator filters / amends / expands the
 *   tree, then hands it to `signer.issue(csr)`:
 *   narrow `sans` to the order's authorised set,
 *   fill the issuer, validity, AIA / CRL DP URLs from
 *   policy, attach any deployment-specific extensions
 *   to `extensions`. The signer reads the tree,
 *   allocates a serial, signs, and returns the
 *   certificate — it does not consult any field the
 *   orchestrator has not already filled.
 *
 * ASN.1 DER is canonical, so re-encoding the typed
 * fields produces the bytes the cert TBS needs.
 * `der` preserves the original wire form for audit
 * and re-parse fallback.
 *
 * Values returned from `parseCSR` are PoP-verified
 * by construction — the consumer need not re-check
 * the self-signature.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc2986}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc5280}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.4}
 */
export type CSR = {
  /** Original DER bytes (RFC 2986 §4). */
  der: Uint8Array

  /** Subject DN; often empty for ACME CSRs. */
  subject: DistinguishedName

  /**
   * Subject public key exported as a branded {@link JWK}.
   * Proof-of-possession over the CSR was checked
   * against this key before the value was produced.
   */
  subjectPublicKey: JWK

  /**
   * Subject Alternative Names, re-shaped as ACME
   * {@link Identifier}s (`dns` + `ip` only). Wire
   * CSRs carrying other SAN types are rejected by
   * `parseCSR` (RFC 8555 §7.1.4, RFC 8738).
   */
  sans: Identifier[]

  /** RFC 5280 §4.2.1.9 BasicConstraints. */
  basicConstraints?: BasicConstraints

  /** RFC 5280 §4.2.1.3 KeyUsage. */
  keyUsage?: KeyUsage[]

  /** RFC 5280 §4.2.1.12 ExtendedKeyUsage purposes. */
  extendedKeyUsage?: ExtendedKeyUsage[]

  /** RFC 5280 §4.2.1.4 CertificatePolicies — OID list. */
  certificatePolicies?: string[]

  /** RFC 5280 §4.2.2.1 AuthorityInfoAccess. */
  authorityInfoAccess?: AuthorityInfoAccess

  /**
   * RFC 5280 §4.2.1.13 CRL distribution-point URIs.
   * Non-URI distribution-point forms are not
   * modelled here; if a wire CSR carries them, they
   * fall through to {@link extensions} and the
   * orchestrator decides whether to keep them.
   */
  crlDistributionPoints?: string[]

  /** Issuer DN — orchestrator-supplied. */
  issuer?: DistinguishedName

  /** Validity start — orchestrator-supplied. */
  notBefore?: Date

  /** Validity end — orchestrator-supplied. */
  notAfter?: Date

  /**
   * Other extensions, identified by OID and carried
   * as raw DER. Used for both wire-CSR extensions
   * outside the typed slots above and for
   * orchestrator-added deployment-specific
   * extensions. Order matches the signer's emit
   * order — the orchestrator can reorder if a
   * deployment cares.
   */
  extensions?: Extension[]
};
