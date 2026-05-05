// CSR schema (RFC 2986, RFC 5280, RFC 8555 §7.4)

import * as v from 'valibot';

import { IdentifierSchema } from './identifier';
import { JWKSchema } from './jwk';

/**
 * RFC 5280 §4.2.1.3 KeyUsage bit names, sorted to
 * match the {@link KeyUsage} type alias.
 */
const KEY_USAGES = [
  'cRLSign',
  'dataEncipherment',
  'decipherOnly',
  'digitalSignature',
  'encipherOnly',
  'keyAgreement',
  'keyCertSign',
  'keyEncipherment',
  'nonRepudiation',
] as const;

/**
 * {@link DistinguishedName} schema — structural check
 * for an array of RDN records (attribute → values).
 *
 * @remarks
 * Attribute short-names (`CN`, `O`, `OU`, `C`, …) and
 * their value strings are not validated here; that's
 * the x509 encoder's concern. This schema only verifies
 * the outer shape is a sequence of attribute-keyed
 * records, matching `@peculiar/x509`'s `JsonName`
 * (`Array<Record<string, string[]>>`).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4}
 */
export const DistinguishedNameSchema = v.array(
  v.record(v.string(), v.array(v.string())),
);

/** RFC 5280 §4.2.1.3 KeyUsage picklist schema. */
export const KeyUsageSchema = v.picklist(KEY_USAGES);

/**
 * RFC 5280 §4.2.1.9 BasicConstraints schema.
 *
 * @remarks
 * `pathLength` is meaningful only when `ca` is `true`
 * — the schema admits a stand-alone `pathLength` so
 * orchestrators can express partial intent during
 * filter / amend passes; the signer enforces the
 * coupling at TBS encode time.
 */
export const BasicConstraintsSchema = v.strictObject({
  ca: v.boolean(),
  pathLength: v.optional(v.pipe(
    v.number(), v.integer(), v.minValue(0),
  )),
});

/**
 * RFC 5280 §4.2.2.1 AuthorityInfoAccess schema —
 * URLs the relying party uses to fetch the issuer
 * chain and OCSP responses.
 */
export const AuthorityInfoAccessSchema = v.strictObject({
  caIssuers: v.optional(v.array(v.string())),
  ocsp: v.optional(v.array(v.string())),
});

/**
 * Generic OID-keyed extension schema for OIDs the
 * {@link CSRSchema} doesn't model first-class.
 *
 * @remarks
 * Structural only — the DER `value` is opaque to
 * this schema; downstream consumers (the signer's
 * TBS encoder, custom extension parsers) handle it.
 */
export const ExtensionSchema = v.strictObject({
  id: v.string(),
  critical: v.optional(v.boolean()),
  value: v.instance(Uint8Array),
});

/**
 * {@link CSR} schema — structural validator for the
 * decoded PKCS#10 + RFC 5280 TBS shape produced by
 * `parseCSR` and amended by the orchestrator.
 *
 * @remarks
 * Structural check only — the proof-of-possession
 * signature is a crypto concern handled by `parseCSR`,
 * not by this schema. Use the schema at RPC / storage
 * boundaries to guard against malformed plain-object
 * inputs; use `parseCSR` wherever a PEM CSR needs to
 * be decoded and verified for the first time.
 *
 * `sans` elements go through {@link IdentifierSchema},
 * so trees carrying a SAN type outside `dns` / `ip`
 * fail validation — matching ACME's admissible
 * identifiers (RFC 8555 §7.1.4, RFC 8738).
 *
 * Every TBS slot the orchestrator may amend is
 * declared here as optional. `strictObject` rejects
 * unknown keys — adding a slot to {@link CSR}
 * requires a matching schema update so the conformance
 * check stays green.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc2986}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc5280}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.4}
 */
export const CSRSchema = v.strictObject({
  der: v.instance(Uint8Array),
  subject: DistinguishedNameSchema,
  subjectPublicKey: JWKSchema,
  sans: v.array(IdentifierSchema),
  basicConstraints: v.optional(BasicConstraintsSchema),
  keyUsage: v.optional(v.array(KeyUsageSchema)),
  extendedKeyUsage: v.optional(v.array(v.string())),
  certificatePolicies: v.optional(v.array(v.string())),
  authorityInfoAccess: v.optional(AuthorityInfoAccessSchema),
  crlDistributionPoints: v.optional(v.array(v.string())),
  issuer: v.optional(DistinguishedNameSchema),
  notBefore: v.optional(v.date()),
  notAfter: v.optional(v.date()),
  extensions: v.optional(v.array(ExtensionSchema)),
});
