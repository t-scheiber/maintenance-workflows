// SPDX-License-Identifier: MIT
import {pathToFileURL} from 'node:url';

// Require the observed provider endpoint and an exact literal query token.
// A generic application ID or UUID alone is not an OpenWeather credential.
const endpoint = String.raw`https?://api\.openweathermap\.org[/?]`;
const appid = String.raw`[?&]appid=([a-f0-9]{32})(?:[&"'\\\s]|$)`;
const endpointPattern = new RegExp(endpoint, 'i');
const appidPattern = new RegExp(appid, 'i');

export function containsOpenWeatherCredential(text) {
  return typeof text === 'string' && endpointPattern.test(text) && appidPattern.test(text);
}

export function gitleaksConfig() {
  const rules = [
    ['openweathermap-appid', `${endpoint}[\\s\\S]*?${appid}`],
    ['openweathermap-appid-before-endpoint', `${appid}[\\s\\S]*?${endpoint}`],
  ];
  return '[extend]\nuseDefault = true\n' + rules.map(([id, regex]) => `
[[rules]]
id = "${id}"
description = "Literal OpenWeather appid query token beside its API endpoint"
regex = ${"'".repeat(3)}(?i)${regex}${"'".repeat(3)}
secretGroup = 1
keywords = ["openweathermap.org"]
`).join('');
}


// The exact protected credential predicate, shared without importing account policy.
export function isSecretFreeText(text) {
  return !(typeof text !== 'string' || /(?:sk-or-v1-|gh[pousr]_|github_pat_|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|AKIA[0-9A-Z]{16}|(?:password|api[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*["'][^"']{12,}["'])/i.test(text) || containsOpenWeatherCredential(text));
}

// Scanner reports are untrusted data. Never serialize nested raw fields as audit locations.
export function gitleaksLocations(data) {
  if (!Array.isArray(data)) throw new Error('Invalid secret scanner report');
  return data.map(record => {
    if (!record || typeof record !== 'object' || Array.isArray(record) || typeof record.RuleID !== 'string' || !/^[A-Za-z0-9_.-]{1,160}$/.test(record.RuleID) || typeof record.File !== 'string' || !record.File || record.File.length > 1000 || /[\u0000-\u001f\u007f]/.test(record.File) || !Number.isSafeInteger(record.StartLine) || record.StartLine < 1 || !isSecretFreeText(record.RuleID) || !isSecretFreeText(record.File)) throw new Error('Invalid secret scanner location');
    return {rule: record.RuleID, path: record.File, line: record.StartLine};
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.stdout.write(gitleaksConfig());
}
