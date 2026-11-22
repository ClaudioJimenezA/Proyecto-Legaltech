/**
 * Pure deterministic CVSS v3.1 calculator based on FIRST.org specifications.
 * Zero external dependencies (Pure Layer).
 */

const METRIC_VALUES = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR: {
    U: { N: 0.85, L: 0.62, H: 0.27 },
    C: { N: 0.85, L: 0.68, H: 0.5 },
  },
  UI: { N: 0.85, R: 0.62 },
  C: { H: 0.56, L: 0.22, N: 0.0 },
  I: { H: 0.56, L: 0.22, N: 0.0 },
  A: { H: 0.56, L: 0.22, N: 0.0 },
};

/**
 * Official FIRST.org rounding algorithm for CVSS v3.1
 */
function roundUp(input) {
  const intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) {
    return intInput / 100000;
  }
  return (Math.floor(intInput / 10000) + 1) / 10;
}

export function parseCvssVector(vectorString) {
  if (typeof vectorString !== 'string') {
    throw new Error('El vector CVSS debe ser una cadena de texto.');
  }

  const parts = vectorString.trim().split('/');
  const prefix = parts[0];
  if (prefix !== 'CVSS:3.1' && prefix !== 'CVSS:3.0') {
    throw new Error(`Prefijo de vector no soportado: ${prefix}`);
  }

  const metrics = {};
  for (let i = 1; i < parts.length; i++) {
    const [key, val] = parts[i].split(':');
    if (key && val) {
      metrics[key] = val;
    }
  }

  const required = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
  for (const req of required) {
    if (!metrics[req]) {
      throw new Error(`Métrica obligatoria faltante en vector: ${req}`);
    }
  }

  return metrics;
}

export function calculateCvssScore(vectorInput) {
  const metrics = typeof vectorInput === 'string' ? parseCvssVector(vectorInput) : vectorInput;

  const scopeChanged = metrics.S === 'C';
  const prScope = scopeChanged ? 'C' : 'U';

  const av = METRIC_VALUES.AV[metrics.AV];
  const ac = METRIC_VALUES.AC[metrics.AC];
  const pr = METRIC_VALUES.PR[prScope]?.[metrics.PR];
  const ui = METRIC_VALUES.UI[metrics.UI];

  const c = METRIC_VALUES.C[metrics.C];
  const i = METRIC_VALUES.I[metrics.I];
  const a = METRIC_VALUES.A[metrics.A];

  if ([av, ac, pr, ui, c, i, a].some((v) => v === undefined)) {
    throw new Error('Métricas CVSS inválidas proporcionadas.');
  }

  // ISS = 1 - [ (1 - ImpactConf) * (1 - ImpactInteg) * (1 - ImpactAvail) ]
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);

  let impact = 0;
  if (scopeChanged) {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  } else {
    impact = 6.42 * iss;
  }

  const exploitability = 8.22 * av * ac * pr * ui;

  let baseScore = 0;
  if (impact <= 0) {
    baseScore = 0.0;
  } else if (!scopeChanged) {
    baseScore = roundUp(Math.min(impact + exploitability, 10));
  } else {
    baseScore = roundUp(Math.min(1.08 * (impact + exploitability), 10));
  }

  const severity = getSeverityRating(baseScore);

  return {
    baseScore: Number(baseScore.toFixed(1)),
    severity,
    vectorString:
      typeof vectorInput === 'string'
        ? vectorInput
        : `CVSS:3.1/AV:${metrics.AV}/AC:${metrics.AC}/PR:${metrics.PR}/UI:${metrics.UI}/S:${metrics.S}/C:${metrics.C}/I:${metrics.I}/A:${metrics.A}`,
    metrics,
  };
}

export function getSeverityRating(score) {
  if (score === 0) return 'NONE';
  if (score < 4.0) return 'LOW';
  if (score < 7.0) return 'MEDIUM';
  if (score < 9.0) return 'HIGH';
  return 'CRITICAL';
}
