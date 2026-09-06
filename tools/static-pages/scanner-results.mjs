// Scanner reports are data. Validate every projected location before emitting any findings.
import {validateOsvReport,validateSemgrepReport,validateTrivyConfigReport} from './scanner-schema.mjs';
import {gitleaksLocations,isSecretFreeText} from './secret-patterns.mjs';
export function sourceFindings(scanner,data){
 const validate={osv:validateOsvReport,semgrep:validateSemgrepReport,trivy:validateTrivyConfigReport,gitleaks:gitleaksLocations}[scanner];
 if(typeof validate!=='function')throw Error('Unknown source scanner');
 const findings=validate(data);
 if(findings.some(finding=>Object.values(finding).some(value=>typeof value==='string'&&!isSecretFreeText(value))))throw Error('Unsafe scanner location');
 return findings;
}
