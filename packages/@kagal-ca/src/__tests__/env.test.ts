import { env } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';

describe('workerd environment', () => {
  it('provides CA_REGISTRY KV binding', () => {
    expect(env.CA_REGISTRY).toBeDefined();
  });

  it('can read and write KV', async () => {
    await env.CA_REGISTRY.put('test-key', 'test-value');
    const value = await env.CA_REGISTRY.get('test-key');
    expect(value).toBe('test-value');
  });
});
