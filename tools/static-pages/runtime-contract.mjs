// SPDX-License-Identifier: MIT
// Public-only complete runtime evidence policy. No repository inventory or credentials.
import fs from 'node:fs';
import {createHash} from 'node:crypto';
import {validateRuntimeScan} from './runtime-scan.mjs';
import {loadRuntime} from './pages-build.mjs';
import {validateRuntimeExecution} from './runtime-database.mjs';
const sha=value=>createHash('sha256').update(value).digest('hex');
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
export function runtimePolicy(kind){
 if(!['node22','node24','semgrep'].includes(kind))throw Error('Unrecognized public runtime');
 const file=kind==='node22'?'runtime-coverage.json':kind==='node24'?'node24-runtime.json':'semgrep-runtime.json';
 const policy=JSON.parse(fs.readFileSync(new URL('./'+file,import.meta.url)));
 if(kind==='node22')return {...policy,kind,baseImage:loadRuntime().image,configId:loadRuntime().provenance.imageId,recipeSha256:null};
 const recipe=fs.readFileSync(new URL('./'+(kind==='node24'?'Node24':'Semgrep')+'.Dockerfile',import.meta.url));
 if(sha(recipe)!==policy.recipeSha256||policy.platform!=='linux/amd64')throw Error('Runtime recipe identity differs');
 if(kind==='node24'){
  if(policy.image!=='personal-maintenance-node24:24.20.0'||policy.baseImage!==loadRuntime().image||policy.nodeVersion!=='v24.20.0'||policy.npmVersion!=='12.0.2')throw Error('Node24 source-free policy differs');
  const base=runtimePolicy('node22');return {...policy,kind,requiredTargets:base.requiredTargets,requiredPackages:base.requiredPackages,os:base.os};
 }
 if(policy.baseImage!=='semgrep/semgrep:1.176.0@sha256:d39aa8d8cdb7fd9e5ec14f0825e2356f902129778c9617217856295e553254d5'||policy.requireFreshCompleteScan!==true||policy.os?.family!=='alpine')throw Error('Semgrep source-free policy differs');
 return {...policy,kind};
}
export function validatePreparedRuntime(kind,{receipt,report,stderr,actualConfigId,runIdentity,scannerIdentity}){
 const policy=runtimePolicy(kind);
 if(!receipt||receipt.status!=='PASS'||receipt.kind!==kind||receipt.platform!=='linux/amd64'||receipt.sourceContext!==false||receipt.credentialsPassed!==false||receipt.baseImage!==policy.baseImage||receipt.recipeSha256!==policy.recipeSha256||!/^sha256:[a-f0-9]{64}$/.test(receipt.executionImage||'')||receipt.configId!==actualConfigId||!same(receipt.runIdentity,runIdentity)||receipt.reportSha256!==sha(report)||receipt.stderrSha256!==sha(stderr)||!same(receipt.scannerIdentity,scannerIdentity))throw Error('Runtime preparation receipt differs');
 if(kind==='node22'&&actualConfigId!==policy.configId)throw Error('Anonymous runtime config differs');
 const parsed=JSON.parse(report);validateRuntimeExecution(receipt.scan,parsed);
 const result=validateRuntimeScan(parsed,{status:0,imageId:actualConfigId,platform:'linux/amd64',stderr:stderr.toString(),requiredTargets:policy.requiredTargets,requiredPackages:policy.requiredPackages,expectedCoverage:policy.expectedCoverage,scannerIdentity});
 if(!same(result.os,policy.os))throw Error('Runtime OS identity differs');
 return {kind,executionImage:receipt.executionImage,configId:actualConfigId,coverage:result};
}
