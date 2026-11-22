/**
 * Pure cryptographic and canonical JSON utilities for WebCrypto in browser/frontend.
 * Zero external dependencies (Pure Layer).
 */

function normalizeValue(val) {
  if (val === null || val === undefined) return null;
  if (val instanceof Date) return val.toISOString();
  if (Array.isArray(val)) {
    return val.map(normalizeValue);
  }
  if (typeof val === 'object') {
    const sorted = {};
    const keys = Object.keys(val).sort();
    for (const k of keys) {
      sorted[k] = normalizeValue(val[k]);
    }
    return sorted;
  }
  return val;
}

export function canonicalizeJson(data) {
  const normalized = normalizeValue(data);
  return JSON.stringify(normalized);
}

export async function computeSha256(data) {
  const canonicalStr = typeof data === 'string' ? data : canonicalizeJson(data);
  const encoder = new TextEncoder();
  const bytes = encoder.encode(canonicalStr);

  if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
    const buffer = await window.crypto.subtle.digest('SHA-256', bytes);
    const hashArray = Array.from(new Uint8Array(buffer));
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  // Fallback for Node.js test environment (Vitest)
  const nodeCrypto = await import('node:crypto');
  return nodeCrypto.createHash('sha256').update(bytes).digest('hex');
}

export async function verifySha256(data, expectedHash) {
  if (!expectedHash || expectedHash.length !== 64) return false;
  const computed = await computeSha256(data);
  return computed.toLowerCase() === expectedHash.toLowerCase();
}

export function generateScopeToken(prefix = 'LXP') {
  const randomBytes = new Uint8Array(6);
  if (typeof window !== 'undefined' && window.crypto && window.crypto.getRandomValues) {
    window.crypto.getRandomValues(randomBytes);
  } else {
    for (let i = 0; i < 6; i++) {
      randomBytes[i] = Math.floor(Math.random() * 256);
    }
  }
  const hex = Array.from(randomBytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
  return `${prefix}-${hex}`;
}
