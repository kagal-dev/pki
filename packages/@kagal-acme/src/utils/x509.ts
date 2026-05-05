// Centralised re-exports of `@peculiar/x509` symbols used
// in `@kagal/acme/utils` and its tests. Keeps the
// `reflect-metadata` polyfill bootstrap in one place —
// `@peculiar/x509`'s tsyringe dependency injection needs
// `Reflect.metadata` defined before any of its classes
// evaluate, so this module imports the polyfill before the
// re-exports.
//
// `Pkcs10CertificateRequestGenerator` is test-only — it
// constructs CSRs from raw key material for fixtures. It is
// re-exported here (not from `utils/index.ts`) so test files
// reach `@peculiar/x509` through the same polyfill-bootstrapped
// barrel as production code, without leaking the generator
// to package consumers.
//
// `Extension` is renamed to `X509Extension` here to avoid a
// collision with `@kagal/acme/types`'s plain-data
// `Extension` shape — `parseCSR` consumes both: the
// peculiar wrapper coming out of the parser, and the
// serialisable form that flows through the orchestrator.
//
// `X509Certificate` and `X509CertificateGenerator` are
// also test-only at the `@kagal/acme` layer — the package
// itself never builds certs (signing is `@kagal/ca`'s
// concern). They sit here so the round-trip test can
// prove a `CSR` tree round-trips through to a signed,
// verifiable certificate without leaking the symbols
// onto the package surface.

import 'reflect-metadata';

export {
  AuthorityInfoAccessExtension,
  BasicConstraintsExtension,
  CertificatePolicyExtension,
  CRLDistributionPointsExtension,
  ExtendedKeyUsageExtension,
  GeneralName,
  KeyUsageFlags,
  KeyUsagesExtension,
  PemConverter,
  Pkcs10CertificateRequest,
  Pkcs10CertificateRequestGenerator,
  SubjectAlternativeNameExtension,
  X509Certificate,
  X509CertificateGenerator,
  Extension as X509Extension,
} from '@peculiar/x509';
