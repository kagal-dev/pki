// Directory schema (RFC 8555 §7.1.1)

import * as v from 'valibot';

/**
 * {@link DirectoryMeta} schema.
 *
 * @remarks
 * Uses `looseObject` — unknown fields pass through.
 * Includes Profiles `profiles`
 * (draft-ietf-acme-profiles) extension.
 * `termsOfService` and `website` are validated via
 * the WHATWG `URL` parser; `caaIdentities` entries
 * are free-form DNS authority strings per RFC 8659
 * and kept as plain strings.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.1}
 */
export const DirectoryMetaSchema = v.looseObject({
  termsOfService: v.optional(v.pipe(v.string(), v.url())),
  website: v.optional(v.pipe(v.string(), v.url())),
  caaIdentities: v.optional(v.array(v.string())),
  externalAccountRequired: v.optional(v.boolean()),
  profiles: v.optional(v.record(v.string(), v.string())),
});

/**
 * {@link Directory} schema.
 *
 * @remarks
 * Uses `looseObject` — unknown fields pass through.
 * All operation endpoints are validated via the
 * WHATWG `URL` parser.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.1}
 */
export const DirectorySchema = v.looseObject({
  newNonce: v.pipe(v.string(), v.url()),
  newAccount: v.pipe(v.string(), v.url()),
  newOrder: v.pipe(v.string(), v.url()),
  newAuthz: v.optional(v.pipe(v.string(), v.url())),
  revokeCert: v.pipe(v.string(), v.url()),
  keyChange: v.pipe(v.string(), v.url()),
  renewalInfo: v.optional(v.pipe(v.string(), v.url())),
  meta: v.optional(DirectoryMetaSchema),
});
