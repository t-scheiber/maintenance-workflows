// Only sanitized manifests reach the networked installer. Source runs offline without credentials.
import fs from 'node:fs';
import path from 'node:path';
import {spawnSync,execFileSync} from 'node:child_process';
import {createHash,randomUUID} from 'node:crypto';
import {npmInstallationInputs} from './npm-lock.mjs';
import {archiveIdentity} from './runtime-archive.mjs';
import {transportLimits} from './runtime-transport.mjs';
import {preparedScanner} from './prepared-scanners.mjs';
import {validateRuntimeScan} from './runtime-scan.mjs';
export function archiveTransport(value){
 if(value?.compression!=='gzip'||!Number.isSafeInteger(value.archiveBytes)||value.archiveBytes<1||value.archiveBytes>transportLimits.artifactBytes||!Number.isSafeInteger(value.expandedArchiveBytes)||value.expandedArchiveBytes<1024||value.expandedArchiveBytes>transportLimits.expandedBytes||!(/^[a-f0-9]{64}$/).test(value.archiveSha256||'')||!(/^[a-f0-9]{64}$/).test(value.expandedArchiveSha256||''))throw Error('Bounded gzip archive identity incomplete');
 return value;
}
export function runtimeBinding(data){
 if(data?.schema!==1||data.status!=='verified-public-runtime'||!/^ghcr\.io\/t-scheiber\/maintenance-node22@sha256:[a-f0-9]{64}$/.test(data.image||''))throw Error('Public runtime is not bound to a reviewed immutable digest');
 const p=data.provenance;
 if(!p||p.image!==data.image||p.anonymousPullVerified!==true||p.activationReady!==true||!/^sha256:[a-f0-9]{64}$/.test(p.imageId||'')||!/^\d+$/.test(p.runId||'')||p.runAttempt!==1||!(/^[a-f0-9]{40}$/).test(p.sourceRevision||'')||p.scanner?.result!=='PASS'||p.scanner?.scope!=='complete-image'||p.platform!=='linux/amd64')throw Error('Runtime provenance incomplete');
 archiveTransport(p);
 const versions={node:'22.23.2',npm:'12.0.2',bun:'1.4.2',npmPatches:{'brace-expansion':'5.0.9','ip-address':'10.3.1',tar:'7.5.21'}};
 if(JSON.stringify(data.runtime)!==JSON.stringify(versions)||JSON.stringify(p.runtime)!==JSON.stringify(versions))throw Error('Runtime contract differs');
 return data;
}
export function loadRuntime(){return runtimeBinding(JSON.parse(fs.readFileSync(new URL('./runtime.json',import.meta.url))));}
export function validateBoundRuntimeScan(data,status,imageId,stderr){
 const policy=JSON.parse(fs.readFileSync(new URL('./runtime-coverage.json',import.meta.url)));
 const binding=loadRuntime();
 if(policy.schema!==1||policy.imageId!==imageId||imageId!==binding.provenance.imageId||policy.platform!=='linux/amd64')throw Error('Runtime coverage policy differs from the reviewed image');
 const result=validateRuntimeScan(data,{status,imageId,platform:policy.platform,stderr,requiredTargets:policy.requiredTargets,requiredPackages:policy.requiredPackages,expectedCoverage:policy.expectedCoverage});
 if(result.os.family!==policy.os.family||result.os.name!==policy.os.name)throw Error('Runtime OS coverage differs from reviewed image');
 return result;
}
function boundedEvidence(filename,max){
 const stat=fs.lstatSync(filename);if(!stat.isFile()||stat.isSymbolicLink()||stat.size>max)throw Error('Runtime evidence missing or oversized');
 return fs.readFileSync(filename,'utf8');
}

export function inspectSource(root){
 let files=0,total=0;
 function walk(dir){for(const item of fs.readdirSync(dir,{withFileTypes:true})){
  if(dir===root&&item.name==='.git')continue;
  const filename=path.join(dir,item.name),stat=fs.lstatSync(filename);
  if(item.name==='node_modules'||item.name==='dist'||stat.isSymbolicLink()||!stat.isDirectory()&&!stat.isFile())throw Error('Untrusted source layout');
  if(stat.isDirectory())walk(filename);else{files++;total+=stat.size;if(files>1000||stat.size>2_000_000||total>30_000_000)throw Error('Source bounds exceeded');}
 }}walk(root);
}
export function profile(pkg){
 for(const [key,value] of Object.entries({test:'node --test tests/*.test.mjs',validate:'node scripts/validate.mjs',build:'node scripts/build.mjs'}))if(pkg.scripts?.[key]!==value)throw Error('Unreviewed static command');
}
if(process.argv[1]&&path.resolve(process.argv[1])===import.meta.filename){
 const root=process.cwd(),temp=process.env.RUNNER_TEMP;
 if(!temp)throw Error('Explicit runner temporary directory required');
 const binding=loadRuntime();
 const admitted=preparedScanner('project');
 const exported=archiveTransport(archiveIdentity(path.join(temp,'runtime-node22/runtime.tar.gz')));
 const actual=admitted.runtime.configId,coverage=admitted.runtime.coverage;
 if(actual!==binding.provenance.imageId)throw Error('Prepared project runtime differs');
 fs.writeFileSync(path.join(temp,'runtime-coverage.json'),JSON.stringify(coverage,null,2));
 inspectSource(root);
 const manifest=fs.readFileSync('package.json','utf8'),pkg=JSON.parse(manifest);profile(pkg);
 const inputs=npmInstallationInputs(manifest,fs.readFileSync('package-lock.json','utf8'));
 const directory=fs.mkdtempSync(path.join(temp,'manifests-'));fs.chmodSync(directory,0o755);
 fs.writeFileSync(path.join(directory,'package.json'),inputs.manifest);fs.writeFileSync(path.join(directory,'package-lock.json'),inputs.lock);
 const name='pages-'+randomUUID();
 function run(args,input,timeout=180000){const result=spawnSync(admitted.dockerCommand,args,{env:admitted.dockerEnvironment,input,timeout,maxBuffer:32_000_000});if(result.status!==0||result.error)throw Error('Bounded container operation failed');return result.stdout;}
 const execute=command=>run(['exec','--user','1000:1000',name,'sh','-c',command]);
 const receipt={head:process.env.GITHUB_SHA,image:binding.image,executionImage:admitted.runtimeImage,imageId:actual,node:'22.23.2',npm:'12.0.2',packages:inputs.packages,runtimeArchive:exported,runtimeCoverage:coverage,commands:[],credentials:false,network:'pending'};
 try{
  run(['run','--detach','--name',name,'--platform','linux/amd64','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','256','--cpus','2','--memory','3g','--tmpfs','/tmp:rw,nosuid,nodev,size=512m','--tmpfs','/work:rw,exec,nosuid,nodev,size=3g,mode=1777','--workdir','/work','--env','HOME=/tmp','--env','CI=true','--env','NPM_CONFIG_CACHE=/tmp/npm-cache','--env','NPM_CONFIG_USERCONFIG=/dev/null','--env','NPM_CONFIG_GLOBALCONFIG=/tmp/empty-npmrc','--mount',`type=bind,src=${directory},dst=/manifests,readonly`,'--entrypoint','/bin/sleep',admitted.runtimeImage,'1000']);
  execute('node -e \'if(process.version!=="v22.23.2")throw Error("Node mismatch");for(const[n,v]of [["brace-expansion","5.0.9"],["ip-address","10.3.1"],["tar","7.5.21"]])if(require("/usr/local/maintenance-npm/node_modules/"+n+"/package.json").version!==v)throw Error("Unpatched npm");\' && test "$(npm --version)" = 12.0.2');
  execute('touch /tmp/empty-npmrc && cp /manifests/* /work/ && npm ci --ignore-scripts --no-audit --no-fund --registry=https://registry.npmjs.org --strict-peer-deps --engine-strict --fetch-retries=0 --fetch-timeout=60000 --allow-git=none --allow-remote=none --allow-file=none --allow-directory=none');
  run(['network','disconnect','bridge',name]);
  if(run(['inspect','--format','{{json .NetworkSettings.Networks}}',name]).toString().trim()!=='{}')throw Error('Network isolation failed');
  const archive=execFileSync('tar',['--exclude=./.git','-cf','-','.'],{timeout:30000,maxBuffer:32_000_000,env:{...process.env,COPYFILE_DISABLE:'1'}});
  run(['exec','-i','--user','1000:1000',name,'tar','--no-same-owner','--no-same-permissions','--no-overwrite-dir','-xf','-','-C','/work'],archive);
  execute('node -e \'const fs=require("fs"),os=require("os");for(const k of ["GH_TOKEN","GITHUB_TOKEN","OPENROUTER_API_KEY","ACTIONS_RUNTIME_TOKEN"])if(process.env[k])throw Error("Credential in sandbox");if(fs.existsSync("/var/run/docker.sock")||Object.values(os.networkInterfaces()).flat().some(x=>!x.internal))throw Error("Isolation failed");\' && rm -rf /tmp/npm-cache');
  receipt.network='none';
  for(const command of ['npm test','npm run validate','npm run build']){execute(command);receipt.commands.push({command,result:'PASS'});}
  const output=run(['exec','--user','1000:1000',name,'tar','-C','/work/dist','-cf','-','.']);
  if(output.length>11_000_000)throw Error('Build artifact exceeds bound');
  fs.writeFileSync(path.join(temp,'static-dist.tar'),output);receipt.artifactSha256=createHash('sha256').update(output).digest('hex');
  if(process.env.GITHUB_OUTPUT)fs.appendFileSync(process.env.GITHUB_OUTPUT,`archive_sha256=${receipt.artifactSha256}\n`);
 }finally{spawnSync(admitted.dockerCommand,['rm','-f',name],{env:admitted.dockerEnvironment,timeout:30000,stdio:'ignore'});fs.rmSync(directory,{recursive:true,force:true});fs.writeFileSync(path.join(temp,'build-receipt.json'),JSON.stringify(receipt,null,2));}
}
