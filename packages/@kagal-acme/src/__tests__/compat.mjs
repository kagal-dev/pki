/**
 * Standalone compatibility smoke test — no test framework
 * required. Two jobs: confirm each built dist entry imports
 * without exploding on the current Node version, then
 * exercise the runtime primitives most prone to break
 * across Node versions / runtimes. A clean import never
 * touches btoa/atob, the random source, or WebCrypto — and
 * WebCrypto algorithm support is the usual fault line — so
 * those are called for real. Shape and behaviour coverage
 * lives in the vitest suite.
 */

/* global console, process, crypto */
/* eslint unicorn/no-process-exit: "off" */

const entries = ['index', 'client', 'schema', 'server', 'types', 'utils'];

let failures = 0;
let version = '?';

function pass(name, detail) {
  console.log(`  ok ${name}${detail ? ' ' + detail : ''}`);
}

function fail(name, reason) {
  console.error(`  FAIL ${name}: ${reason}`);
  failures++;
}

console.log(`Node ${process.version}`);

// 1. Every declared entry must import without exploding.
for (const entry of entries) {
  try {
    const ns = await import(`../../dist/${entry}.mjs`);
    if (entry === 'index') {
      version = ns.VERSION;
    }
    pass(`${entry}.mjs`, `(${Object.keys(ns).length} exports)`);
  } catch (error) {
    fail(`${entry}.mjs`, error.message);
  }
}

console.log(`@kagal/acme v${version}`);

// 2. Exercise the compatibility-prone runtime primitives.
try {
  const { encodeBase64url, decodeBase64url, getRandom, jwkThumbprint, exportJWK } =
    await import('../../dist/utils.mjs');

  // base64url round-trip — exercises the btoa / atob globals.
  const bytes = new Uint8Array([0, 1, 2, 125, 126, 127, 253, 254, 255]);
  const out = new Uint8Array(decodeBase64url(encodeBase64url(bytes)));
  if (out.length === bytes.length && out.every((b, index) => b === bytes[index])) {
    pass('base64url round-trip (btoa/atob)');
  } else {
    fail('base64url round-trip', `got [${out}]`);
  }

  // Random source — exercises crypto.getRandomValues.
  const nonce = getRandom(16);
  if (typeof nonce === 'string' && nonce.length > 0) {
    pass('getRandom (getRandomValues)', `(${nonce.length} chars)`);
  } else {
    fail('getRandom', `expected base64url string, got ${typeof nonce}`);
  }

  // WebCrypto digest — RFC 7638 thumbprint of a known EC JWK.
  const kid = await jwkThumbprint({
    kty: 'EC',
    crv: 'P-256',
    x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
    y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
  });
  if (typeof kid === 'string' && kid.length === 43) {
    pass('jwkThumbprint (subtle.digest)', `= '${kid}'`);
  } else {
    fail('jwkThumbprint', `expected 43-char base64url, got '${kid}'`);
  }

  // WebCrypto key generation + JWK export — algorithm support
  // is the most version-sensitive part of the surface.
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  const jwk = await exportJWK(pair.publicKey);
  if (jwk.kty === 'EC' && jwk.crv === 'P-256') {
    pass('exportJWK (subtle key gen)', `(${jwk.kty}/${jwk.crv})`);
  } else {
    fail('exportJWK', `unexpected JWK kty=${jwk.kty} crv=${jwk.crv}`);
  }
} catch (error) {
  fail('crypto primitives', error.message);
}

if (failures > 0) {
  const label = failures === 1 ? 'check' : 'checks';
  console.error(`\n${failures} ${label} failed`);
  process.exit(1);
} else {
  console.log(`ok ${process.version} — loaded and exercised`);
}
