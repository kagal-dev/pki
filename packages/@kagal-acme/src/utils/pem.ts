// PEM encode/decode helpers (RFC 7468)

import { ProblemError } from '../error';
import { asPEM, type PEM } from '../types';

import { PemConverter } from './x509';

/**
 * Decode a single PEM block and assert its label.
 *
 * @param pem - armoured text (already brand-validated
 *   upstream via {@link PEMSchema} or `asPEM`).
 * @param label - expected PEM label (e.g.
 *   `'CERTIFICATE REQUEST'`, `'CERTIFICATE'`,
 *   `'PUBLIC KEY'`). RFC 7468 spells labels in
 *   upper-case, space-separated.
 * @returns Raw DER bytes of the single decoded block.
 *
 * @remarks
 * Rejects inputs whose first block carries a different
 * label than `label` — catches the "certificate PEM
 * passed where a CSR was expected" mistake at the trust
 * boundary. Concatenated chains (multiple blocks) are
 * rejected too; use a chain-aware helper when that
 * shape is wanted.
 *
 * @throws {@link ProblemError} with the
 *   `urn:ietf:params:acme:error:malformed` URN if
 *   `pem` contains no PEM block, more than one block,
 *   a block whose label does not match `label`, or
 *   armour the underlying decoder cannot parse
 *   (unclosed line, invalid base64, etc.).
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7468}
 */
export function decodePEM(
  pem: PEM,
  label: string,
): Uint8Array<ArrayBuffer> {
  let blocks: ReturnType<typeof PemConverter.decodeWithHeaders>;
  try {
    blocks = PemConverter.decodeWithHeaders(pem);
  } catch (error) {
    throw ProblemError.malformed(
      'PEM armour is structurally broken',
      { cause: error },
    );
  }
  if (blocks.length === 0) {
    throw ProblemError.malformed('PEM input contains no blocks');
  }
  if (blocks.length > 1) {
    throw ProblemError.malformed(
      `PEM input contains ${blocks.length} blocks; expected one`,
    );
  }
  const [block] = blocks;
  if (block.type !== label) {
    throw ProblemError.malformed(
      `PEM label mismatch: expected ${label}, got ${block.type}`,
    );
  }
  return new Uint8Array(block.rawData);
}

/**
 * Encode raw bytes as a single {@link PEM} block with
 * the given label.
 *
 * @param bytes - raw DER (or any `BufferSource`).
 * @param label - PEM label (e.g.
 *   `'CERTIFICATE REQUEST'`). RFC 7468 spells labels in
 *   upper-case, space-separated.
 *
 * @remarks
 * Thin wrapper over `@peculiar/x509`'s `PemConverter`
 * that brands the output. Producers that already have a
 * typed PEM string (e.g. `csr.toString('pem')`) should
 * keep the peculiar output and use {@link asPEM}
 * instead of re-encoding.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7468}
 */
export function encodePEM(bytes: BufferSource, label: string): PEM {
  return asPEM(PemConverter.encode(bytes, label));
}
