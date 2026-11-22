import { describe, expect, it } from 'vitest';
import {
  canonicalizeJson,
  computeSha256,
  generateScopeToken,
  verifySha256,
} from './crypto_utils.js';

describe('crypto_utils Pure Layer', () => {
  it('canonicalizes JSON sorting object keys deterministically', () => {
    const objA = { z: 1, a: 2, m: { y: 10, x: 20 } };
    const objB = { a: 2, m: { x: 20, y: 10 }, z: 1 };

    expect(canonicalizeJson(objA)).toBe(canonicalizeJson(objB));
    expect(canonicalizeJson(objA)).toBe('{"a":2,"m":{"x":20,"y":10},"z":1}');
  });

  it('computes 64-character SHA-256 hash matching expected value', async () => {
    const payload = { title: 'RoE Test', version: 1 };
    const hash = await computeSha256(payload);

    expect(hash).toHaveLength(64);
    expect(await verifySha256(payload, hash)).toBe(true);
    expect(await verifySha256({ title: 'RoE Modificado' }, hash)).toBe(false);
  });

  it('generates formatted scope tokens', () => {
    const token = generateScopeToken('LXP');
    expect(token).toMatch(/^LXP-[A-F0-9]{12}$/);
  });
});
