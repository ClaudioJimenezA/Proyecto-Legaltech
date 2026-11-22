import { describe, expect, it } from 'vitest';
import {
  isValidAsset,
  isValidCidr,
  isValidFqdn,
  isValidIpv4,
  isRestrictedStateDomain,
  validateAuditorSourceIps,
  validateScopeList,
} from './network_validators.js';

describe('network_validators Pure Layer', () => {
  it('validates IPv4 addresses properly', () => {
    expect(isValidIpv4('192.168.1.1')).toBe(true);
    expect(isValidIpv4('200.10.20.30')).toBe(true);
    expect(isValidIpv4('256.1.1.1')).toBe(false);
    expect(isValidIpv4('not-an-ip')).toBe(false);
  });

  it('validates CIDR ranges properly', () => {
    expect(isValidCidr('200.10.20.0/24')).toBe(true);
    expect(isValidCidr('10.0.0.0/8')).toBe(true);
    expect(isValidCidr('200.10.20.0/33')).toBe(false);
    expect(isValidCidr('200.10.20.0')).toBe(false);
  });

  it('validates FQDN domains properly', () => {
    expect(isValidFqdn('api.cliente.cl')).toBe(true);
    expect(isValidFqdn('*.portal.empresa.com')).toBe(true);
    expect(isValidFqdn('localhost')).toBe(false);
    expect(isValidFqdn('-invalid-.cl')).toBe(false);
  });

  it('detects restricted Chilean state and military domains', () => {
    expect(isRestrictedStateDomain('portal.gob.cl')).toBe(true);
    expect(isRestrictedStateDomain('defensa.mil.cl')).toBe(true);
    expect(isRestrictedStateDomain('bancoestado.cl')).toBe(false);
    expect(isRestrictedStateDomain('miempresa.cl')).toBe(false);
  });

  it('validates scope lists and flags conflicts with excluded assets', () => {
    const res = validateScopeList(
      ['api.empresa.cl', 'portal.gob.cl', '190.20.30.0/24'],
      ['190.20.30.0/24']
    );
    expect(res.isValid).toBe(false);
    expect(res.errors.some((e) => e.includes('estatal'))).toBe(true);
    expect(res.errors.some((e) => e.includes('Conflicto'))).toBe(true);
  });

  it('rejects private IPs for auditor source IPs', () => {
    const res = validateAuditorSourceIps(['192.168.1.50', '200.50.20.10']);
    expect(res.isValid).toBe(false);
    expect(res.errors.some((e) => e.includes('privada'))).toBe(true);

    const validRes = validateAuditorSourceIps(['200.50.20.10']);
    expect(validRes.isValid).toBe(true);
  });
});
