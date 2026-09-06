// SPDX-License-Identifier: MIT
// Re-read exact native and runtime evidence before repository data reaches a scanner.
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {admitSourceScanners} from '../native/source-admission.mjs';
import {preparationIdentity} from './prepare-runtime.mjs';
import {validatePreparedRuntime} from './runtime-contract.mjs';
import {archiveIdentity} from './runtime-archive.mjs';
const hash=data=>createHash('sha256').update(data).digest('hex');
function read(file,limit){let fd;try{fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);const s=fs.fstatSync(fd);if(!s.isFile()||s.size>limit)throw Error('Prepared scanner evidence bounds');const bytes=fs.readFileSync(fd);if(bytes.length!==s.size)throw Error('Prepared scanner evidence changed');return bytes;}finally{if(fd!==undefined)fs.closeSync(fd);}}
export function preparedScanner(scanner,{env=process.env,execute=spawnSync,nativeAdmission=admitSourceScanners,inspectArchive=archiveIdentity}={}){
 if(!['osv','trivy','gitleaks','semgrep','project'].includes(scanner))throw Error('Unknown source scanner');
 const runIdentity=preparationIdentity(env),root=env.RUNNER_TEMP;
 if(!root||!path.isAbsolute(root)||!fs.lstatSync(root).isDirectory()||fs.lstatSync(root).isSymbolicLink())throw Error('Trusted scanner evidence directory required');
 const native=nativeAdmission(path.join(root,'native-bundle-verification/fresh'));
 const kind=scanner==='semgrep'?'semgrep':scanner==='project'?'node22':'node24',directory=path.join(root,'runtime-'+kind);
 if(!fs.lstatSync(directory).isDirectory()||fs.lstatSync(directory).isSymbolicLink())throw Error('Runtime preparation directory differs');
 const receipt=JSON.parse(read(path.join(directory,'receipt.json'),100000));
 const actual=inspectArchive(path.join(directory,'runtime.tar.gz'));if(actual.platform!=='linux/amd64'||actual.compression!=='gzip')throw Error('Runtime archive platform differs');
 const trivyHash=hash(read(native.binaries.trivy,400_000_000));
 const validated=validatePreparedRuntime(kind,{receipt,report:read(path.join(directory,'report.json'),32_000_000),stderr:read(path.join(directory,'stderr.log'),2_000_000),actualConfigId:actual.imageId,runIdentity,scannerIdentity:{version:'0.74.0+maintenance.1',sha256:trivyHash}});
 const command=process.platform==='darwin'?'/usr/local/bin/docker':'/usr/bin/docker';const dockerConfig=path.join(directory,'docker-config');
 if(!fs.lstatSync(dockerConfig).isDirectory()||fs.lstatSync(dockerConfig).isSymbolicLink()||fs.readdirSync(dockerConfig).length)throw Error('Runtime Docker configuration changed');
 const dockerBin=path.join(directory,'docker-bin'),dockerLink=path.join(dockerBin,'docker');
 if(!fs.lstatSync(dockerBin).isDirectory()||fs.lstatSync(dockerBin).isSymbolicLink()||JSON.stringify(fs.readdirSync(dockerBin))!==JSON.stringify(['docker'])||!fs.lstatSync(dockerLink).isSymbolicLink()||fs.readlinkSync(dockerLink)!==command)throw Error('Runtime Docker executable directory changed');
 const dockerEnvironment={PATH:dockerBin,DOCKER_CONFIG:dockerConfig,...env.DOCKER_HOST?{DOCKER_HOST:env.DOCKER_HOST}:{}};
 const result=execute(command,['image','inspect',validated.executionImage],{env:dockerEnvironment,encoding:'utf8',timeout:30000,maxBuffer:2_000_000});
 if(result.error||result.status!==0)throw Error('Prepared runtime is unavailable');const rows=JSON.parse(result.stdout);if(!Array.isArray(rows)||rows.length!==1||rows[0].Id!==validated.executionImage||rows[0].Os!=='linux'||rows[0].Architecture!=='amd64')throw Error('Prepared runtime execution identity differs');
 const tool=scanner==='osv'?'osv-scanner':scanner;
 return {scanner,dockerCommand:command,dockerEnvironment,runtimeImage:validated.executionImage,executable:['semgrep','project'].includes(scanner)?null:native.binaries[tool],runtime:validated,native:native.receipts,runIdentity};
}
