/**
 * Pure syntactic and regulatory scope validation for pentesting assets in frontend.
 * Zero external dependencies (Pure Layer).
 */

const FQDN_REGEX =
  /^(?:\*\.)?(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;

export const RESTRICTED_STATE_SUFFIXES = [
  '.gob.cl',
  '.gov.cl',
  '.mil.cl',
  '.defensa.cl',
  '.ejercito.cl',
  '.armada.cl',
  '.fach.cl',
  '.carabineros.cl',
  '.pdi.cl',
];

export function isValidIpv4(ip) {
  if (typeof ip !== 'string') return false;
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return false;
  for (const p of parts) {
    if (!/^\d+$/.test(p)) return false;
    const n = Number(p);
    if (n < 0 || n > 255 || (p.length > 1 && p.startsWith('0'))) return false;
  }
  return true;
}

export function isValidIpv6(ip) {
  if (typeof ip !== 'string') return false;
  const s = ip.trim();
  const ipv6Regex =
    /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
  return ipv6Regex.test(s);
}

export function isValidCidr(cidr) {
  if (typeof cidr !== 'string' || !cidr.includes('/')) return false;
  const [ip, mask] = cidr.trim().split('/');
  if (!mask || !/^\d+$/.test(mask)) return false;
  const m = Number(mask);
  if (isValidIpv4(ip)) {
    return m >= 0 && m <= 32;
  }
  if (isValidIpv6(ip)) {
    return m >= 0 && m <= 128;
  }
  return false;
}

export function isValidFqdn(domain) {
  if (typeof domain !== 'string') return false;
  const cleaned = domain.trim().replace(/\.$/, '').toLowerCase();
  return FQDN_REGEX.test(cleaned);
}

export function isValidAsset(asset) {
  if (!asset || typeof asset !== 'string') return false;
  const cleaned = asset.trim();
  return isValidIpv4(cleaned) || isValidIpv6(cleaned) || isValidCidr(cleaned) || isValidFqdn(cleaned);
}

export function isRestrictedStateDomain(asset) {
  if (!asset || typeof asset !== 'string') return false;
  const cleaned = asset.trim().replace(/\.$/, '').toLowerCase();
  return RESTRICTED_STATE_SUFFIXES.some(
    (suffix) => cleaned.endsWith(suffix) || cleaned === suffix.replace(/^\./, '')
  );
}

export function isPrivateIpv4(ip) {
  if (!isValidIpv4(ip)) return false;
  const parts = ip.trim().split('.').map(Number);
  if (parts[0] === 10) return true; // 10.0.0.0/8
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true; // 172.16.0.0/12
  if (parts[0] === 192 && parts[1] === 168) return true; // 192.168.0.0/16
  if (parts[0] === 127) return true; // loopback
  return false;
}

export function validateScopeList(targetAssets = [], excludedAssets = [], allowState = false) {
  const errors = [];
  const warnings = [];
  const validAssets = [];

  if (!targetAssets.length) {
    return { isValid: false, errors: ['Debe especificar al menos un activo In-Scope.'], warnings, validAssets };
  }

  const normalizedExcluded = excludedAssets.map((e) => e.trim().toLowerCase());

  for (const raw of targetAssets) {
    const cleaned = raw.trim();
    if (!isValidAsset(cleaned)) {
      errors.push(`Activo inválido: "${raw}". Debe ser FQDN, IP o CIDR.`);
      continue;
    }

    if (isRestrictedStateDomain(cleaned) && !allowState) {
      errors.push(`Activo "${cleaned}" pertenece a dominio estatal/defensa restringido.`);
      continue;
    }

    if (normalizedExcluded.includes(cleaned.toLowerCase())) {
      errors.push(`Conflicto de alcance: "${cleaned}" está en la lista de excluidos.`);
      continue;
    }

    if (isPrivateIpv4(cleaned)) {
      warnings.push(`"${cleaned}" es una IP privada (RFC 1918). Requiere túnel VPN.`);
    }

    validAssets.push(cleaned);
  }

  return {
    isValid: errors.length === 0,
    errors,
    warnings,
    validAssets,
  };
}

export function validateAuditorSourceIps(sourceIps = []) {
  const errors = [];
  const validIps = [];

  if (!sourceIps.length) {
    return { isValid: false, errors: ['Debe enrolar al menos una IP pública de auditor.'], validIps };
  }

  for (const raw of sourceIps) {
    const cleaned = raw.trim();
    const isIp = isValidIpv4(cleaned) || isValidIpv6(cleaned) || isValidCidr(cleaned);
    if (!isIp) {
      errors.push(`IP de origen inválida: "${raw}".`);
      continue;
    }
    const baseIp = cleaned.split('/')[0];
    if (isPrivateIpv4(baseIp)) {
      errors.push(`La IP de origen "${cleaned}" no puede ser privada o loopback. Debe ser pública.`);
      continue;
    }
    validIps.push(cleaned);
  }

  return {
    isValid: errors.length === 0,
    errors,
    validIps,
  };
}
