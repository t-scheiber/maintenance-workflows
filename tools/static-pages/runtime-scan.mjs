// SPDX-License-Identifier: MIT
// Pure report validation. No execution, I/O, credentials or source-specific policy.
import {createHash} from 'node:crypto';
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const text=(value,max=2000)=>typeof value==='string'&&value.length>0&&value.length<=max&&!/[\u0000-\u001f\u007f]/.test(value);
const sha=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
const severities=['UNKNOWN','LOW','MEDIUM','HIGH','CRITICAL'];
function fail(code){throw Object.assign(new Error(`Runtime scan rejected: ${code}`),{code});}
function cleanDiagnostics(value){
 for(const key of ['Errors','Warnings','errors','warnings'])if(Object.hasOwn(value,key)&&(!Array.isArray(value[key])||value[key].length))fail('ANALYSIS_DIAGNOSTIC');
}
function packageIdentity(pkg,type){
 const pythonWithoutId=type==='python-pkg'&&object(pkg)&&!Object.hasOwn(pkg,'ID');
 if(!object(pkg)||(!pythonWithoutId&&!text(pkg.ID))||!text(pkg.Name,512)||!text(pkg.Version,512)||!object(pkg.Identifier)||!text(pkg.Identifier.PURL,4000)||!pkg.Identifier.PURL.startsWith('pkg:'))fail('PACKAGE_IDENTITY');
 if(pythonWithoutId&&(!text(pkg.FilePath,4000)||!pkg.Identifier.PURL.startsWith('pkg:pypi/')))fail('PACKAGE_IDENTITY');
 const identity={ID:pythonWithoutId?null:pkg.ID,Name:pkg.Name,Version:pkg.Version};
 for(const key of ['Release','Arch','SrcName','SrcVersion','SrcRelease','FilePath']){
  if(Object.hasOwn(pkg,key)&&!text(pkg[key],key==='FilePath'?4000:1000))fail('PACKAGE_IDENTITY');
  identity[key]=pkg[key]??null;
 }
 for(const key of ['Epoch','SrcEpoch']){
  if(Object.hasOwn(pkg,key)&&!((Number.isSafeInteger(pkg[key])&&pkg[key]>=0)||(typeof pkg[key]==='string'&&/^\d{1,20}$/.test(pkg[key]))))fail('PACKAGE_IDENTITY');
  identity[key]=pkg[key]??null;
 }
 identity.PURL=pkg.Identifier.PURL;
 return identity;
}
function coverageShape(value){
 if(!object(value)||Object.keys(value).sort().join(',')!=='class,inventorySha256,packages,target,type'||!text(value.class,100)||!text(value.type,100)||!text(value.target,2000)||!Number.isSafeInteger(value.packages)||value.packages<1||!/^[a-f0-9]{64}$/.test(value.inventorySha256||''))fail('EXPECTED_COVERAGE');
 return {class:value.class,type:value.type,target:value.target,packages:value.packages,inventorySha256:value.inventorySha256};
}
export function validateRuntimeScan(report,{status,imageId,platform,stderr,requiredTargets=[],requiredPackages=[],expectedCoverage,scannerIdentity}={}){
 const scannerVersion=scannerIdentity===undefined?'0.74.0':scannerIdentity?.version;
 if(scannerIdentity!==undefined&&(!object(scannerIdentity)||Object.keys(scannerIdentity).sort().join(',')!=='sha256,version'||scannerIdentity.version!=='0.74.0+maintenance.1'||scannerIdentity.sha256!=='d60fd11532d37ffcfd73b71de9cd09159f337aaaf6ad7d28a0d9c8870d4657fc'))fail('SCANNER_IDENTITY');
 if(status!==0||!/^sha256:[a-f0-9]{64}$/.test(imageId||'')||!['linux/amd64','linux/arm64'].includes(platform)||typeof stderr!=='string'||Buffer.byteLength(stderr)>2000000)fail('EXECUTION_EVIDENCE');
 if(/\b(?:WARN|WARNING|ERROR|FATAL)\b/i.test(stderr)||/\b(?:vulnerabilit(?:y|ies)[^\r\n]{0,120}details?[^\r\n]{0,120}(?:missing|unavailable|not found)|(?:missing|unavailable|failed to (?:get|fetch|retrieve)|unable to (?:get|fetch|retrieve))[^\r\n]{0,120}vulnerabilit(?:y|ies)[^\r\n]{0,120}details?)\b/i.test(stderr))fail('ANALYSIS_DIAGNOSTIC');
 if(!object(report)||report.SchemaVersion!==2||report.ArtifactType!=='container_image'||report.Trivy?.Version!==scannerVersion||report.Metadata?.ImageID!==imageId)fail('REPORT_IDENTITY');
 cleanDiagnostics(report);
 const metadata=report.Metadata,os=metadata.OS,config=metadata.ImageConfig;
 if(!object(os)||!text(os.Family,100)||!text(os.Name,100)||os.EOSL===true||!object(config)||`${config.os}/${config.architecture}`!==platform)fail('PLATFORM_COVERAGE');
 if(!Array.isArray(report.Results)||!report.Results.length||report.Results.length>1000)fail('RESULT_COVERAGE');
 const targets=[],allPackages=[],counts=Object.fromEntries(severities.map(s=>[s,0]));let packageCount=0;
 for(const result of report.Results){
  if(!object(result)||!text(result.Target)||!['os-pkgs','lang-pkgs'].includes(result.Class)||!text(result.Type,100)||!Array.isArray(result.Packages)||!result.Packages.length)fail('RESULT_COVERAGE');
  cleanDiagnostics(result);
  if(result.Class==='os-pkgs'&&result.Type!==os.Family)fail('PLATFORM_COVERAGE');
  for(const key of ['Misconfigurations','Secrets','Licenses'])if(Object.hasOwn(result,key)&&(!Array.isArray(result[key])||result[key].length))fail('UNEXPECTED_SCANNER_RESULT');
  packageCount+=result.Packages.length;if(packageCount>100000)fail('PACKAGE_BUDGET');
  const identities=result.Packages.map(pkg=>packageIdentity(pkg,result.Type)).sort((a,b)=>Buffer.compare(Buffer.from(JSON.stringify(a)),Buffer.from(JSON.stringify(b))));
  if(new Set(identities.map(p=>JSON.stringify(p))).size!==identities.length)fail('DUPLICATE_PACKAGE');
  const target=result.Class==='os-pkgs'?'operating-system':result.Target;
  targets.push({class:result.Class,type:result.Type,target,packages:identities.length,inventorySha256:sha(identities)});
  for(const item of identities)allPackages.push({class:result.Class,type:result.Type,...item});
  if(Object.hasOwn(result,'Vulnerabilities')&&!Array.isArray(result.Vulnerabilities))fail('VULNERABILITY_SCHEMA');
  if((result.Vulnerabilities?.length||0)>100000)fail('VULNERABILITY_BUDGET');
  const ids=new Map();for(const pkg of identities){if(pkg.ID===null)continue;if(!ids.has(pkg.ID))ids.set(pkg.ID,new Set());ids.get(pkg.ID).add(pkg.Name);}
  for(const vulnerability of result.Vulnerabilities||[]){
   if(!object(vulnerability)||!text(vulnerability.VulnerabilityID,300)||!text(vulnerability.PkgName,512)||!text(vulnerability.InstalledVersion,512)||!severities.includes(vulnerability.Severity))fail('VULNERABILITY_SCHEMA');
   if(result.Type==='python-pkg'&&!Object.hasOwn(vulnerability,'PkgID')){
    if(Object.hasOwn(vulnerability,'PkgPath')&&!text(vulnerability.PkgPath,4000))fail('VULNERABILITY_SCHEMA');
    const matches=identities.filter(pkg=>pkg.ID===null&&pkg.Name===vulnerability.PkgName&&pkg.Version===vulnerability.InstalledVersion&&(!Object.hasOwn(vulnerability,'PkgPath')||pkg.FilePath===vulnerability.PkgPath));
    if(matches.length!==1)fail('VULNERABILITY_PACKAGE');
   }else{
    if(!text(vulnerability.PkgID)||!ids.has(vulnerability.PkgID))fail('VULNERABILITY_SCHEMA');
    if(!ids.get(vulnerability.PkgID)?.has(vulnerability.PkgName))fail('VULNERABILITY_PACKAGE');
   }
   counts[vulnerability.Severity]++;
  }
 }
 targets.sort((a,b)=>Buffer.compare(Buffer.from(JSON.stringify([a.class,a.type,a.target])),Buffer.from(JSON.stringify([b.class,b.type,b.target]))));
 if(new Set(targets.map(t=>JSON.stringify([t.class,t.type,t.target]))).size!==targets.length||targets.filter(t=>t.class==='os-pkgs').length!==1)fail('RESULT_COVERAGE');
 if(!Array.isArray(requiredTargets)||requiredTargets.length>20||!Array.isArray(requiredPackages)||requiredPackages.length>100)fail('EXPECTED_COVERAGE');
 for(const requirement of requiredTargets){
  if(!object(requirement)||Object.keys(requirement).sort().join(',')!=='class,type'||!text(requirement.class,100)||!text(requirement.type,100)||!targets.some(t=>t.class===requirement.class&&t.type===requirement.type))fail('REQUIRED_TARGET');
 }
 const matched=[];
 for(const requirement of requiredPackages){
  if(!object(requirement)||Object.keys(requirement).some(k=>!['class','type','name','version','filePath','id'].includes(k))||!['class','type','name','version'].every(k=>text(requirement[k],1000))||['filePath','id'].some(k=>Object.hasOwn(requirement,k)&&!text(requirement[k],4000)))fail('EXPECTED_COVERAGE');
  const match=allPackages.find(p=>p.class===requirement.class&&p.type===requirement.type&&p.Name===requirement.name&&p.Version===requirement.version&&(!Object.hasOwn(requirement,'filePath')||p.FilePath===requirement.filePath)&&(!Object.hasOwn(requirement,'id')||p.ID===requirement.id));
  if(!match)fail('REQUIRED_PACKAGE');matched.push({...requirement});
 }
 if(expectedCoverage!==undefined){
  if(!Array.isArray(expectedCoverage)||!expectedCoverage.length)fail('EXPECTED_COVERAGE');
  const expected=expectedCoverage.map(coverageShape).sort((a,b)=>Buffer.compare(Buffer.from(JSON.stringify([a.class,a.type,a.target])),Buffer.from(JSON.stringify([b.class,b.type,b.target]))));
  if(JSON.stringify(targets)!==JSON.stringify(expected))fail('INVENTORY_MISMATCH');
 }
 if(counts.UNKNOWN||counts.HIGH||counts.CRITICAL)fail('BLOCKING_VULNERABILITY');
 return {version:1,imageId,platform,scanner:{name:'trivy',version:scannerVersion},os:{family:os.Family,name:os.Name},targets,packages:packageCount,severities:counts,requiredPackages:matched,coverage:'reported OS and language package inventories; manually installed binaries require independent provenance/version checks'};
}
