import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { resolveDocuments } from '../extract';

const __dirname = path.dirname(
  fileURLToPath(import.meta.url),
);

const rootDirectory = path.resolve(__dirname, '../..');
const fixtureInput = path.resolve(
  __dirname, 'fixtures/sample.ts',
);

function makeContext(
  entries: { input: string; name?: string }[],
) {
  return {
    options: {
      rootDir: rootDirectory,
      name: '@test/fixture',
      entries,
    },
    pkg: { version: '1.0.0' },
  } as never;
}

describe('resolveDocuments', () => {
  it('extracts symbols from a TypeScript file', () => {
    const manifest = resolveDocuments(
      makeContext([
        { input: fixtureInput, name: 'sample' },
      ]),
    );

    expect(manifest.name).toBe('@test/fixture');
    expect(manifest.version).toBe('1.0.0');
    expect(manifest.generatedAt).toBeDefined();

    const entry = manifest.exports['./sample'];
    expect(entry).toBeDefined();
    expect(entry.symbolCount).toBeGreaterThanOrEqual(3);

    const names = entry.symbols.map((s) => s.name);
    expect(names).toContain('SAMPLE');
    expect(names).toContain('SampleOptions');
    expect(names).toContain('greet');
  });

  it('maps index entry to root export path', () => {
    const manifest = resolveDocuments(
      makeContext([
        { input: fixtureInput, name: 'index' },
      ]),
    );

    expect(manifest.exports['.']).toBeDefined();
    expect(manifest.exports['./index']).toBeUndefined();
  });

  it('maps undefined name to root export path', () => {
    const manifest = resolveDocuments(
      makeContext([{ input: fixtureInput }]),
    );

    expect(manifest.exports['.']).toBeDefined();
  });

  it('relativises file paths in symbols', () => {
    const manifest = resolveDocuments(
      makeContext([
        { input: fixtureInput, name: 'sample' },
      ]),
    );

    const entry = manifest.exports['./sample'];
    for (const symbol of entry.symbols) {
      if (symbol.fileName) {
        expect(
          path.isAbsolute(symbol.fileName),
        ).toBe(false);
      }
    }
  });

  it('records entry file path relative to root', () => {
    const manifest = resolveDocuments(
      makeContext([
        { input: fixtureInput, name: 'sample' },
      ]),
    );

    const entry = manifest.exports['./sample'];
    expect(entry.entryFile).not.toContain(rootDirectory);
    expect(
      path.isAbsolute(entry.entryFile),
    ).toBe(false);
  });

  it('handles multiple entries', () => {
    const manifest = resolveDocuments(
      makeContext([
        { input: fixtureInput, name: 'index' },
        { input: fixtureInput, name: 'extras' },
      ]),
    );

    expect(manifest.exports['.']).toBeDefined();
    expect(manifest.exports['./extras']).toBeDefined();
    expect(
      Object.keys(manifest.exports),
    ).toHaveLength(2);
  });

  it('extracts class constructors and methods', () => {
    const manifest = resolveDocuments(
      makeContext([
        { input: fixtureInput, name: 'sample' },
      ]),
    );

    const entry = manifest.exports['./sample'];
    const names = entry.symbols.map((s) => s.name);
    expect(names).toContain('Greeter');
  });

  it('records entries with no documented symbols', () => {
    const manifest = resolveDocuments(
      makeContext([
        {
          input: path.join(
            __dirname, 'fixtures/non-existent.ts',
          ),
          name: 'missing',
        },
      ]),
    );

    const entry = manifest.exports['./missing'];
    expect(entry).toBeDefined();
    expect(entry.symbolCount).toBe(0);
  });
});
