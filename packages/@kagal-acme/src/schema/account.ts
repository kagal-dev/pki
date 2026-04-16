// Account schema (RFC 8555 §7.1.2)

import * as v from 'valibot';

import {
  accountStatuses,
} from '../types/constants/status';

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
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.2}
 */
export const AccountSchema = v.looseObject({
  status: v.picklist(accountStatuses),
  contact: v.optional(
    v.array(v.pipe(v.string(), v.url())),
  ),
  termsOfServiceAgreed: v.optional(v.boolean()),
  externalAccountBinding: v.optional(FlattenedJWSSchema),
  orders: v.pipe(v.string(), v.url()),
});
