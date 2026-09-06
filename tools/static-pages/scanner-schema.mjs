// Scanner JSON is untrusted data. Return only bounded finding locations, never raw messages or source.
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const own = (value, key) => Object.hasOwn(value, key);
const invalid = scanner => { throw new Error(`Invalid ${scanner} scanner report`); };
function text(value, scanner, limit = 1000) {
  if (typeof value !== 'string' || !value.length || value.length > limit || /[\u0000-\u001f\u007f]/u.test(value)) invalid(scanner);
  return value;
}
function list(value, scanner) {
  if (!Array.isArray(value) || value.length > 50000) invalid(scanner);
  return value;
}
function identifier(value, scanner) {
  text(value, scanner, 200);
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:/+-]*$/.test(value)) invalid(scanner);
  return value;
}
function position(value, scanner) {
  if (!object(value) || !Number.isSafeInteger(value.line) || value.line < 1) invalid(scanner);
  for (const field of ['col', 'offset']) if (own(value, field) && (!Number.isSafeInteger(value[field]) || value[field] < (field === 'col' ? 1 : 0))) invalid(scanner);
  return value.line;
}
function findingsBound(findings, scanner) {
  if (findings.length > 50000) invalid(scanner);
  return findings;
}

// OSV's clean status-0 output has results:[], even when dependencies were scanned.
// The documented exit-128 dependency-free exception belongs to the caller, not this validator.
export function validateOsvReport(data) {
  const scanner = 'OSV', findings = [];
  if (!object(data)) invalid(scanner);
  for (const result of list(data.results, scanner)) {
    if (!object(result) || !object(result.source)) invalid(scanner);
    text(result.source.path, scanner); text(result.source.type, scanner, 100);
    for (const entry of list(result.packages, scanner)) {
      if (!object(entry) || !object(entry.package)) invalid(scanner);
      for (const field of ['name', 'version', 'ecosystem']) text(entry.package[field], scanner);
      for (const vulnerability of list(entry.vulnerabilities, scanner)) {
        if (!object(vulnerability)) invalid(scanner);
        findings.push({id: identifier(vulnerability.id, scanner)});
        findingsBound(findings, scanner);
      }
    }
  }
  return findings;
}

export function validateSemgrepReport(data) {
  const scanner = 'Semgrep';
  if (!object(data) || !object(data.paths)) invalid(scanner);
  text(data.version, scanner, 100);
  const results = list(data.results, scanner), errors = list(data.errors, scanner);
  if (errors.length) invalid(scanner);
  for (const path of list(data.paths.scanned, scanner)) text(path, scanner);
  return results.map(result => {
    if (!object(result)) invalid(scanner);
    const finding = {rule: identifier(result.check_id, scanner), path: text(result.path, scanner), line: position(result.start, scanner)};
    if (own(result, 'end')) {
      position(result.end, scanner);
      if (result.end.line < result.start.line || own(result.start, 'offset') && own(result.end, 'offset') && result.end.offset < result.start.offset) invalid(scanner);
    }
    // extra may contain raw source, messages, fixes and metadata. Never return it.
    if (own(result, 'extra') && !object(result.extra)) invalid(scanner);
    return finding;
  });
}

const severities = new Set(['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
export function validateTrivyConfigReport(data) {
  const scanner = 'Trivy configuration', findings = [];
  if (!object(data) || data.SchemaVersion !== 2 || !['filesystem', 'repository'].includes(data.ArtifactType)) invalid(scanner);
  text(data.ArtifactName, scanner);
  // Current Trivy omits Results when no applicable configuration or package target exists.
  // Scope-specific expected-target coverage remains a caller responsibility.
  if (!own(data, 'Results')) return findings;
  for (const result of list(data.Results, scanner)) {
    if (!object(result) || !['config', 'lang-pkgs', 'os-pkgs'].includes(result.Class)) invalid(scanner);
    const path = text(result.Target, scanner); text(result.Type, scanner, 100);
    if (own(result, 'Packages')) for (const pkg of list(result.Packages, scanner)) {
      if (!object(pkg)) invalid(scanner);
      text(pkg.Name, scanner);
      if (own(pkg, 'Version')) text(pkg.Version, scanner);
    }
    if (own(result, 'Vulnerabilities')) {
      // A config-only invocation must not silently discard dependency vulnerabilities.
      if (list(result.Vulnerabilities, scanner).length) invalid(scanner);
    }
    if (result.Class !== 'config') {
      if (!own(result, 'Packages') || own(result, 'MisconfSummary') || own(result, 'Misconfigurations')) invalid(scanner);
      continue;
    }
    if (!object(result.MisconfSummary)) invalid(scanner);
    for (const field of ['Successes', 'Failures']) if (!Number.isSafeInteger(result.MisconfSummary[field]) || result.MisconfSummary[field] < 0) invalid(scanner);
    if (own(result.MisconfSummary, 'Exceptions') && (!Number.isSafeInteger(result.MisconfSummary.Exceptions) || result.MisconfSummary.Exceptions < 0)) invalid(scanner);
    const entries = own(result, 'Misconfigurations') ? list(result.Misconfigurations, scanner) : [];
    if (result.MisconfSummary.Failures > 0 && !entries.length) invalid(scanner);
    for (const entry of entries) {
      if (!object(entry) || !severities.has(entry.Severity)) invalid(scanner);
      const id = identifier(entry.ID, scanner);
      if (own(entry, 'Status') && !['FAIL', 'PASS', 'EXCEPTION'].includes(entry.Status)) invalid(scanner);
      // Keep the existing configuration severity policy. Do not invent a new approval or severity gate.
      if (['HIGH', 'CRITICAL'].includes(entry.Severity)) findings.push({id, path, severity: entry.Severity});
      findingsBound(findings, scanner);
    }
  }
  return findings;
}
