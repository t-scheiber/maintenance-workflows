// SPDX-License-Identifier: MIT
// Two fixed source-free recipes. No repository context, credentials or mutable execution tags.
import fs from 'node:fs';
import path from 'node:path';
import {createHash,randomUUID} from 'node:crypto';
import {spawn,spawnSync} from 'node:child_process';
import {packRuntime} from './runtime-transport.mjs';
import {archiveIdentity} from './runtime-archive.mjs';
import {runtimePolicy,validatePreparedRuntime} from './runtime-contract.mjs';
import {admitSourceScanners} from '../native/source-admission.mjs';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const immutable=value=>{if(typeof value!=='string'||!/^sha256:[a-f0-9]{64}$/.test(value))throw Error('Immutable runtime reference required');return value;};
export function preparationIdentity(env){
 const ids={'t-scheiber/AK_WeatherApp':'755321462','t-scheiber/ScheiberVueAppAbgabe':'755319788','t-scheiber/maintenance-workflows':'1359178236'};
 if(env.GITHUB_REPOSITORY_OWNER_ID!=='66697291'||ids[env.GITHUB_REPOSITORY]!==env.GITHUB_REPOSITORY_ID||env.PUBLIC_REPOSITORY_PRIVATE!=='false')throw Error('Fixed public owner/repository identity required');
 const result={repository:env.GITHUB_REPOSITORY,run:env.GITHUB_RUN_ID,attempt:env.GITHUB_RUN_ATTEMPT,source:env.GITHUB_SHA,tools:env.PUBLIC_TOOLS_REF};
 if(!/^t-scheiber\/(AK_WeatherApp|ScheiberVueAppAbgabe|maintenance-workflows)$/.test(result.repository||'')||!/^\d+$/.test(result.run||'')||!/^\d+$/.test(result.attempt||'')||![result.source,result.tools].every(x=>/^[a-f0-9]{40}$/.test(x||'')))throw Error('Trusted public run identity required');
 if(['GH_TOKEN','GITHUB_TOKEN','OPENROUTER_API_KEY','MAINTENANCE_APP_PRIVATE_KEY','ACTIONS_RUNTIME_TOKEN'].some(k=>env[k]))throw Error('Runtime preparation requires a credential-free environment');
 return result;
}
function read(file,limit){let fd;try{fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);const s=fs.fstatSync(fd);if(!s.isFile()||s.size<1||s.size>limit)throw Error('Runtime evidence bounds');const data=fs.readFileSync(fd);if(data.length!==s.size)throw Error('Runtime evidence changed');return data;}finally{if(fd!==undefined)fs.closeSync(fd);}}
export async function saveRuntimeImage(image,archive,env,launch=spawn,{timeoutMs=180000,cleanupMs=5000}={}){
 if(!Number.isInteger(timeoutMs)||timeoutMs<1||timeoutMs>180000||!Number.isInteger(cleanupMs)||cleanupMs<1||cleanupMs>5000)throw Error('Invalid save deadline');
 const child=launch('docker',['image','save',image],{stdio:['ignore','pipe','pipe'],env});let stderr='';
 child.stderr.on('data',chunk=>{stderr+=chunk.toString();if(Buffer.byteLength(stderr)>1000000)child.kill('SIGKILL');});
 const completed=new Promise((resolve,reject)=>{child.once('error',()=>reject(Error('Node runtime save failed')));child.once('close',code=>code===0?resolve():reject(Error('Node runtime save failed')));});
 // Observe rejection immediately while streaming so process errors cannot become unhandled.
 completed.catch(()=>{});
 let deadline,cleanupTimer;
 const timedOut=new Promise((resolve,reject)=>{deadline=setTimeout(()=>{child.kill('SIGKILL');child.stdout.destroy(Error('Node runtime save deadline exceeded'));reject(Error('Node runtime save deadline exceeded'));},timeoutMs);});timedOut.catch(()=>{});
 try{const transport=await Promise.race([packRuntime(child.stdout,archive),timedOut]);await Promise.race([completed,timedOut]);if(Buffer.byteLength(stderr)>1000000)throw Error('Node runtime save diagnostics exceeded bounds');return transport;}
 catch(error){child.kill('SIGKILL');await Promise.race([completed.catch(()=>{}),new Promise(resolve=>{cleanupTimer=setTimeout(resolve,cleanupMs);})]);throw error;}
 finally{clearTimeout(deadline);clearTimeout(cleanupTimer);}

}
function checked(execute,args,env,extra={}){const r=execute('docker',args,{env,timeout:180000,maxBuffer:2_000_000,...extra});if(r.error||r.status!==0)throw Error('Bounded runtime container operation failed');return r.stdout;}
export async function prepareRuntime(kind,{env=process.env,execute=spawnSync,save=saveRuntimeImage,nativeAdmission=admitSourceScanners}={}){
 if(!['node22','node24','semgrep'].includes(kind))throw Error('Unknown fixed source-free runtime');
 const runIdentity=preparationIdentity(env),policy=runtimePolicy(kind),temporary=env.RUNNER_TEMP;
 if(!temporary||!path.isAbsolute(temporary)||!fs.lstatSync(temporary).isDirectory()||fs.lstatSync(temporary).isSymbolicLink())throw Error('Trusted runner temporary directory required');
 // Native source authority remains a separate required gate, never inferred from diagnostic success.
 const native=nativeAdmission(path.join(temporary,'native-bundle-verification/fresh'));
 const scanner=native.binaries.trivy,scannerIdentity={version:'0.74.0+maintenance.1',sha256:sha(read(scanner,400_000_000))};
 if(scannerIdentity.sha256!=='d60fd11532d37ffcfd73b71de9cd09159f337aaaf6ad7d28a0d9c8870d4657fc')throw Error('Admitted scanner binary differs');
 const directory=path.join(temporary,'runtime-'+kind);fs.mkdirSync(directory,{mode:0o700});
 const dockerConfig=path.join(directory,'docker-config'),dockerBin=path.join(directory,'docker-bin');fs.mkdirSync(dockerConfig,{mode:0o700});fs.mkdirSync(dockerBin,{mode:0o700});fs.symlinkSync(process.platform==='darwin'?'/usr/local/bin/docker':'/usr/bin/docker',path.join(dockerBin,'docker'));
 const childEnv={PATH:dockerBin,DOCKER_CONFIG:dockerConfig,...env.DOCKER_HOST?{DOCKER_HOST:env.DOCKER_HOST}:{}};
 const receipt={schema:1,status:'BLOCK',kind,platform:'linux/amd64',baseImage:policy.baseImage,recipeSha256:policy.recipeSha256,runIdentity,sourceContext:false,credentialsPassed:false};
 try{
  let tag;
  if(kind==='node22'){tag=policy.baseImage;checked(execute,['pull','--platform','linux/amd64',tag],childEnv,{timeout:600000});}
  else{
   const recipe=read(new URL('./'+(kind==='node24'?'Node24':'Semgrep')+'.Dockerfile',import.meta.url),20_000);if(sha(recipe)!==policy.recipeSha256)throw Error('Source-free recipe changed');
   tag=kind==='node24'?'personal-maintenance-node24:24.20.0':'personal-maintenance-semgrep:1.176.0-patched';
   checked(execute,['build','--platform','linux/amd64','--build-arg','TARGETARCH=amd64','--tag',tag,'-'],childEnv,{input:recipe,timeout:900000});
  }
  const inspection=JSON.parse(checked(execute,['image','inspect',tag],childEnv));if(!Array.isArray(inspection)||inspection.length!==1||inspection[0].Os!=='linux'||inspection[0].Architecture!=='amd64')throw Error('Runtime build platform differs');receipt.executionImage=immutable(inspection[0].Id);
  const archive=path.join(directory,'runtime.tar.gz');receipt.transport=await save(receipt.executionImage,archive,childEnv);const parsed=archiveIdentity(archive);if(parsed.platform!=='linux/amd64'||parsed.compression!=='gzip')throw Error('Runtime archive identity differs');receipt.configId=parsed.imageId;
  const output=path.join(directory,'scan');fs.mkdirSync(output,{mode:0o700});
  fs.writeFileSync(path.join(output,'trivy.yaml'),'{}\n',{flag:'wx',mode:0o600});fs.writeFileSync(path.join(output,'ignore'),'\n',{flag:'wx',mode:0o600});
  const containerName='public-runtime-scan-'+randomUUID();
  const args=['run','--name',containerName,'--platform','linux/amd64','--network','bridge','--read-only','--user',`${process.getuid()}:${process.getgid()}`,'--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','128','--memory','2g','--cpus','2','--tmpfs','/tmp:rw,nosuid,nodev,size=128m','--env','HOME=/tmp','--mount',`type=bind,src=${scanner},dst=/scanner,readonly`,'--mount',`type=bind,src=${output},dst=/out`,'--mount',`type=bind,src=${archive},dst=/runtime.tar.gz,readonly`,'--entrypoint','/scanner',runtimePolicy('node22').baseImage,'image','--input','/runtime.tar.gz','--config','/out/trivy.yaml','--ignorefile','/out/ignore','--cache-dir','/out/trivy-cache','--scanners','vuln','--list-all-pkgs','--severity','UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL','--exit-code','0','--format','json','--output','/out/report.json'];
  let scan;try{scan=execute('docker',args,{env:childEnv,timeout:600000,maxBuffer:2_000_000});}finally{checked(execute,['rm','-f',containerName],childEnv,{timeout:30000});}const stderr=Buffer.from(scan.stderr??'');fs.writeFileSync(path.join(directory,'stderr.log'),stderr,{flag:'wx',mode:0o600});if(scan.error||scan.status!==0)throw Error('Complete runtime scanner failed');
  const report=read(path.join(output,'report.json'),32_000_000);fs.linkSync(path.join(output,'report.json'),path.join(directory,'report.json'));receipt.reportSha256=sha(report);receipt.stderrSha256=sha(stderr);receipt.status='PASS';receipt.scannerIdentity=scannerIdentity;
  receipt.coverage=validatePreparedRuntime(kind,{receipt,report,stderr,actualConfigId:receipt.configId,runIdentity,scannerIdentity}).coverage;
  return receipt;
 }catch(error){receipt.status='BLOCK';receipt.reason='RUNTIME_PREPARATION_FAILED';throw Error('Runtime preparation blocked');}
 finally{fs.writeFileSync(path.join(directory,'receipt.json'),JSON.stringify(receipt,null,2)+'\n',{flag:'wx',mode:0o600});}
}
if(process.argv[1]&&path.resolve(process.argv[1])===import.meta.filename){const [kind,...extra]=process.argv.slice(2);if(extra.length)throw Error('Unexpected runtime arguments');const receipt=await prepareRuntime(kind);if(process.env.GITHUB_OUTPUT)fs.appendFileSync(process.env.GITHUB_OUTPUT,`execution_image=${receipt.executionImage}\nconfig_id=${receipt.configId}\n`);console.log(JSON.stringify({kind:receipt.kind,status:receipt.status,configId:receipt.configId,coverage:receipt.coverage}));}
