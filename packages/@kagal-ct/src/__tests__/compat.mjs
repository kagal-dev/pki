/**
 * Standalone compatibility smoke test — no test framework
 * required. Confirms each built dist entry imports without
 * exploding on the current Node version. That's all: shape
 * and behaviour coverage lives in the vitest suite.
 */

/* global console, process */
/* eslint unicorn/no-process-exit: "off" */

const entries = ['index', 'schema', 'types'];

let failures = 0;
let version = '?';

console.log(`Node ${process.version}`);

for (const entry of entries) {
  try {
    const ns = await import(`../../dist/${entry}.mjs`);
    if (entry === 'index') {
      version = ns.VERSION;
    }
    console.log(`  ok ${entry}.mjs (${Object.keys(ns).length} exports)`);
  } catch (error) {
    console.error(`  FAIL ${entry}.mjs: ${error.message}`);
    failures++;
  }
}

console.log(`@kagal/ct v${version}`);

if (failures > 0) {
  const label = failures === 1 ? 'entry' : 'entries';
  console.error(`\n${failures} ${label} failed to load`);
  process.exit(1);
} else {
  console.log(`ok ${process.version} — all entries loaded`);
}
