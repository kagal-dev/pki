// Account schema (RFC 8555 §7.1.2)

import * as v from 'valibot';

import { accountStatuses } from '../types';

import { FlattenedJWSSchema } from './jws';

/**
 * {@link Account} schema.
 *
 * @remarks
 * Uses `looseObject` — unknown fields pass through.
 * `externalAccountBinding` is validated as a
 * {@link FlattenedJWSSchema} (structural alias).
 * `contact` entries are URI-shaped (`mailto:`, `tel:`,
 * etc.) — validated via the WHATWG `URL` parser so
 * any scheme that produces an absolute URI passes.
 *
 * `orders` is listed as required by RFC 8555 §7.1.2,
 * but Boulder (Let's Encrypt) and other production CAs
 * omit it from account responses — Boulder's
 * `Registration` struct in `core/objects.go` has no
 * `Orders` field at all. Relaxed to optional for
 * real-world interop; consumers that need it can
 * narrow on presence at the call site.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.2}
 */
export const AccountSchema = v.looseObject({
  status: v.picklist(accountStatuses),
  contact: v.optional(
    v.array(v.pipe(v.string(), v.url())),
  ),
  termsOfServiceAgreed: v.optional(v.boolean()),
  externalAccountBinding: v.optional(FlattenedJWSSchema),
  orders: v.optional(v.pipe(v.string(), v.url())),
});
