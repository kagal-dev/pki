// Directory schema (RFC 8555 §7.1.1)

import * as v from 'valibot';

/**
 * {@link DirectoryMeta} schema.
 *
 * @remarks
 * Uses `looseObject` — unknown fields pass through.
 * Includes Profiles `profiles`
 * (draft-ietf-acme-profiles) extension.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.1}
 */
export const DirectoryMetaSchema = v.looseObject({
  termsOfService: v.optional(v.string()),
  website: v.optional(v.string()),
  caaIdentities: v.optional(v.array(v.string())),
  externalAccountRequired: v.optional(v.boolean()),
  profiles: v.optional(v.record(v.string(), v.string())),
});

/**
 * {@link Directory} schema.
 *
 * @remarks
 * Uses `looseObject` — unknown fields pass through.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.1}
 */
export const DirectorySchema = v.looseObject({
  newNonce: v.string(),
  newAccount: v.string(),
  newOrder: v.string(),
  newAuthz: v.optional(v.string()),
  revokeCert: v.string(),
  keyChange: v.string(),
  renewalInfo: v.optional(v.string()),
  meta: v.optional(DirectoryMetaSchema),
});
