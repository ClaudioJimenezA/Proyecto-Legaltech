import { describe, expect, it } from 'vitest';
import {
  calculateCvssScore,
  getSeverityRating,
  parseCvssVector,
} from './cvss_calculator.js';

describe('cvss_calculator Pure Layer', () => {
  it('parses CVSS v3.1 vector string correctly', () => {
    const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
    const parsed = parseCvssVector(vector);
    expect(parsed.AV).toBe('N');
    expect(parsed.AC).toBe('L');
    expect(parsed.PR).toBe('N');
    expect(parsed.UI).toBe('N');
    expect(parsed.S).toBe('U');
    expect(parsed.C).toBe('H');
    expect(parsed.I).toBe('H');
    expect(parsed.A).toBe('H');
  });

  it('calculates Critical score 9.8 for unauthenticated remote RCE', () => {
    const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
    const result = calculateCvssScore(vector);
    expect(result.baseScore).toBe(9.8);
    expect(result.severity).toBe('CRITICAL');
  });

  it('calculates Medium score 5.4 for Scope Changed Stored XSS', () => {
    const vector = 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N';
    const result = calculateCvssScore(vector);
    expect(result.baseScore).toBe(5.4);
    expect(result.severity).toBe('MEDIUM');
  });

  it('calculates High score 7.8 for local privilege escalation', () => {
    const vector = 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H';
    const result = calculateCvssScore(vector);
    expect(result.baseScore).toBe(7.8);
    expect(result.severity).toBe('HIGH');
  });

  it('calculates Low score 3.1 for complex info disclosure', () => {
    const vector = 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N';
    const result = calculateCvssScore(vector);
    expect(result.baseScore).toBe(3.1);
    expect(result.severity).toBe('LOW');
  });

  it('evaluates severity ratings properly', () => {
    expect(getSeverityRating(0)).toBe('NONE');
    expect(getSeverityRating(3.5)).toBe('LOW');
    expect(getSeverityRating(6.0)).toBe('MEDIUM');
    expect(getSeverityRating(7.5)).toBe('HIGH');
    expect(getSeverityRating(9.5)).toBe('CRITICAL');
  });
});
