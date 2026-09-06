// Exact reviewed maintenance rebuild. A fresh full native scan precedes any workflow input.
import fs from 'node:fs';
import path from 'node:path';
import {randomUUID,createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {isSecretFreeText} from './secret-patterns.mjs';
import {preparedScanner} from './prepared-scanners.mjs';
import {canonical, fingerprint, parseJson, sha256} from '../native/native-admission.mjs';
const policyRoot=fileURLToPath(new URL('../native/policy/',import.meta.url));
const BINARY='5643e67c6bd1a4b37f56e1dec1bd9f9bef37ff8371dd2034908bfde9f6f63947';
const SCANNER='d60fd11532d37ffcfd73b71de9cd09159f337aaaf6ad7d28a0d9c8870d4657fc';
const fail=code=>{throw Object.assign(Error('Actionlint rejected: '+code),{code});};
export function readBounded(file,limit){
 const resolved=path.resolve(file);let parent=path.parse(resolved).root;
 for(const part of resolved.slice(parent.length).split('/').slice(0,-1)){parent=path.join(parent,part);const s=fs.lstatSync(parent);if(!s.isDirectory()||s.isSymbolicLink())fail('FILE_PARENT');}
 let fd;try{fd=fs.openSync(resolved,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);const a=fs.fstatSync(fd);if(!a.isFile()||a.size>limit)fail('FILE_BOUNDS');const data=fs.readFileSync(fd),b=fs.fstatSync(fd);if(data.length!==a.size||a.size!==b.size||a.mtimeMs!==b.mtimeMs||a.ctimeMs!==b.ctimeMs)fail('FILE_CHANGED');return data;}finally{if(fd!==undefined)fs.closeSync(fd);}
}
export function hashBounded(file,limit){
 // Reuse the same parent/type discipline without allocating an entire database.
 const resolved=path.resolve(file);let parent=path.parse(resolved).root;
 for(const part of resolved.slice(parent.length).split('/').slice(0,-1)){parent=path.join(parent,part);const s=fs.lstatSync(parent);if(!s.isDirectory()||s.isSymbolicLink())fail('FILE_PARENT');}
 let fd;try{fd=fs.openSync(resolved,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);const before=fs.fstatSync(fd);if(!before.isFile()||before.size>limit)fail('FILE_BOUNDS');const hash=createHash('sha256'),buffer=Buffer.alloc(1024*1024);let count=0;for(;;){const n=fs.readSync(fd,buffer,0,buffer.length,null);if(!n)break;count+=n;if(count>limit)fail('FILE_BOUNDS');hash.update(buffer.subarray(0,n));}const after=fs.fstatSync(fd);if(count!==before.size||before.size!==after.size||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs)fail('FILE_CHANGED');return hash.digest('hex');}finally{if(fd!==undefined)fs.closeSync(fd);}
}
export function actionlintPolicy(){const value=parseJson(readBounded(path.join(policyRoot,'actionlint-release.json'),100000),'execution');if(value.version!==1||value.repository!=='t-scheiber/maintenance-workflows'||value.binary?.sha256!==BINARY||value.binary?.bytes!==8402983||value.binary?.path!=='bin/actionlint'||value.scan?.scannerSha256!==SCANNER||value.scan?.scannerVersion!=='0.74.0+maintenance.1'||value.scan?.packages!==13||!/^[a-f0-9]{64}$/.test(value.scan?.inventorySha256))fail('POLICY');return value;}
export function requirePublished(policy){if(policy.state!=='published'||policy.assetId!==547382486||policy.releaseId!==383640029||policy.immutable!==true)fail('PUBLICATION_PENDING');}
const noDiagnostics=o=>{for(const k of ['Errors','errors','Warnings','warnings','Vulnerabilities','Misconfigurations','Secrets','Licenses'])if(Object.hasOwn(o,k)&&(!Array.isArray(o[k])||o[k].length))fail('SCANNER_FINDING_OR_DIAGNOSTIC');};
export function inventoryFingerprint(packages){if(!Array.isArray(packages)||packages.length!==13)fail('PACKAGE_COVERAGE');const normalized=packages.map(p=>{if(!p||typeof p!=='object'||typeof p.ID!=='string'||typeof p.Name!=='string'||typeof p.Version!=='string'||typeof p.Identifier?.PURL!=='string'||p.AnalyzedBy!=='gobinary')fail('PACKAGE_IDENTITY');const row=structuredClone(p);delete row.Identifier.UID;return row;});if(new Set(normalized.map(p=>p.ID)).size!==13)fail('PACKAGE_DUPLICATE');normalized.sort((a,b)=>Buffer.compare(Buffer.from(canonical(a)),Buffer.from(canonical(b))));return fingerprint(normalized);}
export function validateActionlintScan({report,stderr,status,binarySha256,scannerSha256,startedAt,finishedAt,database,now},policy=actionlintPolicy()){
 if(status!==0||binarySha256!==BINARY||scannerSha256!==SCANNER)fail('EXECUTION');
 const start=Date.parse(startedAt),end=Date.parse(finishedAt),updated=Date.parse(database?.UpdatedAt),next=Date.parse(database?.NextUpdate),downloaded=Date.parse(database?.DownloadedAt);
 if(!Number.isSafeInteger(now)||![start,end,updated,next,downloaded].every(Number.isFinite)||end<start||end-start>180000||end>now+1000||now-end>300000||updated>start+60000||now-updated>86400000||next<=now||next<=updated||downloaded<updated||downloaded>start+60000||database.Version!==2||!/^[a-f0-9]{64}$/.test(database.sha256))fail('FRESHNESS');
 if(!Buffer.isBuffer(stderr)||stderr.length>2_000_000||!Buffer.from(stderr.toString('utf8')).equals(stderr))fail('DIAGNOSTICS');
 for(const line of stderr.toString('utf8').split(/\r?\n/)){if(!line)continue;if(!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z\tINFO\t[^\x00-\x08\x0a-\x1f\x7f]+$/.test(line)||/(?:missing|unavailable|failed|unable|error|panic|unsupported|unreadable|not found|incomplete|skipped|cannot|exception|fatal)/i.test(line))fail('DIAGNOSTICS');}
 const parsed=parseJson(report);if(parsed.SchemaVersion!==2||parsed.ArtifactType!=='filesystem'||parsed.ArtifactName!=='/input'||parsed.Trivy?.Version!=='0.74.0+maintenance.1'||!Array.isArray(parsed.Results)||parsed.Results.length!==1)fail('REPORT_IDENTITY');noDiagnostics(parsed);
 const created=Date.parse(parsed.CreatedAt);if(!Number.isFinite(created)||created<start-60000||created>end+60000)fail('REPORT_TIME');
 const result=parsed.Results[0];if(result.Target!=='actionlint'||result.Class!=='lang-pkgs'||result.Type!=='gobinary')fail('TARGET');noDiagnostics(result);
 if(inventoryFingerprint(result.Packages)!==policy.scan.inventorySha256)fail('PACKAGE_INVENTORY');
 return {status:'PASS',packages:13,vulnerabilities:0,warnings:0,binarySha256,scannerSha256,inventorySha256:policy.scan.inventorySha256,reportSha256:sha256(report),stderrSha256:sha256(stderr),database,startedAt,finishedAt};
}
export function captureWorkflows(source,destination){
 const dir=path.join(source,'.github/workflows');if(fs.lstatSync(dir).isSymbolicLink()||!fs.lstatSync(dir).isDirectory())fail('WORKFLOWS_DIRECTORY');
 const names=fs.readdirSync(dir).filter(n=>/\.ya?ml$/.test(n)).sort();if(names.length===0||names.length>50)fail('WORKFLOWS_COUNT');
 fs.mkdirSync(destination,{mode:0o755});let total=0;const files=[];
 for(const name of names){if(!/^[A-Za-z0-9_.-]{1,150}\.ya?ml$/.test(name)||!isSecretFreeText(name))fail('WORKFLOW_PATH');const data=readBounded(path.join(dir,name),1_000_000);if((total+=data.length)>4_000_000)fail('WORKFLOWS_BUDGET');fs.writeFileSync(path.join(destination,name),data,{flag:'wx',mode:0o444});files.push({path:name,sha256:sha256(data),bytes:data.length});}return files;
}
export function projectLinterOutput(stdout,stderr){const safe=isSecretFreeText(stdout)&&isSecretFreeText(stderr);return {safe,stdout:safe?stdout:'Linter output withheld: credential-like content detected.\n',stderr:safe?stderr:'Linter output withheld.\n'};}
export function containerArguments(image,entrypoint,mounts){
 if(!/^sha256:[a-f0-9]{64}$/.test(image)||!['/scanner','/actionlint'].includes(entrypoint))fail('CONTAINER_IDENTITY');
 const args=['run','--name','public-actionlint-'+randomUUID(),'--platform','linux/amd64','--network','none','--read-only','--user','1000:1000','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','128','--memory','2g','--cpus','2','--tmpfs','/tmp:rw,nosuid,nodev,size=128m','--workdir','/work','--env','HOME=/tmp'];
 for(const [host,target]of mounts){if(!path.isAbsolute(host)||host.includes(',')||!['/scanner','/actionlint','/input','/cache','/config','/work'].includes(target))fail('MOUNT');args.push('--mount',`type=bind,src=${host},dst=${target},readonly`);}return [...args,'--entrypoint',entrypoint,image];
}
function run(admitted,args,timeout,execute){const name=args[args.indexOf('--name')+1];let result,cleanup;try{result=execute(admitted.dockerCommand,args,{env:admitted.dockerEnvironment,encoding:'utf8',timeout,maxBuffer:32_000_000});}finally{cleanup=execute(admitted.dockerCommand,['rm','-f',name],{env:admitted.dockerEnvironment,encoding:'utf8',timeout:30000,maxBuffer:100000});}if(cleanup.error||cleanup.status!==0)fail('CONTAINER_CLEANUP');return result;}
export function runActionlint({env=process.env,source=process.cwd(),admit=preparedScanner,execute=spawnSync,install=true}={}){
 const admitted=admit('trivy',{env}),policy=actionlintPolicy();requirePublished(policy);
 const root=path.join(env.RUNNER_TEMP,'actionlint');
 if(install){const keys=['GITHUB_ACTIONS','GITHUB_REPOSITORY','GITHUB_REPOSITORY_ID','GITHUB_REPOSITORY_OWNER_ID','PUBLIC_REPOSITORY_PRIVATE','PUBLIC_HEAD_REPOSITORY_ID','GITHUB_SHA','PUBLIC_TOOLS_REF','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_EVENT_NAME','GITHUB_REF','PUBLIC_DEFAULT_BRANCH','STATIC_PAGES_ENABLED','RUNNER_TEMP'];const clean=Object.fromEntries(keys.filter(k=>env[k]!==undefined).map(k=>[k,env[k]]));const result=execute('/usr/bin/python3',[fileURLToPath(new URL('../native/bundle/install_actionlint.py',import.meta.url))],{env:clean,encoding:'utf8',timeout:150000,maxBuffer:100000});if(result.error||result.status!==0)fail('TRANSPORT');}
 const binary=readBounded(path.join(root,'bundle',policy.binary.path),10_000_000);if(binary.length!==policy.binary.bytes||sha256(binary)!==BINARY||sha256(readBounded(admitted.executable,400_000_000))!==SCANNER)fail('BINARY_IDENTITY');
 const input=path.join(root,'input'),config=path.join(root,'config');fs.mkdirSync(input,{mode:0o755});fs.mkdirSync(config,{mode:0o755});const executable=path.join(input,'actionlint');fs.writeFileSync(executable,binary,{flag:'wx',mode:0o555});fs.writeFileSync(path.join(config,'trivy.yaml'),'{}\n',{flag:'wx',mode:0o444});fs.writeFileSync(path.join(config,'ignore'),'',{flag:'wx',mode:0o444});
 const nativeRoot=path.join(env.RUNNER_TEMP,'native-bundle-verification'),cache=path.join(nativeRoot,'database');
 const dbExecution=parseJson(readBounded(path.join(nativeRoot,'fresh/trivy/execution.json'),100000),'execution');
 const database=parseJson(readBounded(path.join(cache,'db/metadata.json'),100000),'execution');
 // The already admitted same-run native proof binds the database. Read it before and after this offline scan.
 database.sha256=hashBounded(path.join(cache,'db/trivy.db'),2_000_000_000);
 for(const key of ['Version','UpdatedAt','NextUpdate','DownloadedAt','sha256'])if(database[key]!==dbExecution.database[key])fail('DATABASE_BINDING');
 const start=new Date().toISOString();const scan=run(admitted,[...containerArguments(admitted.runtimeImage,'/scanner',[[admitted.executable,'/scanner'],[input,'/input'],[cache,'/cache'],[config,'/config']]),'rootfs','--skip-db-update','--offline-scan','--no-progress','--config','/config/trivy.yaml','--ignorefile','/config/ignore','--cache-dir','/cache','--cache-backend','memory','--scanners','vuln','--list-all-pkgs','--severity','UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL','--exit-code','0','--format','json','/input'],180000,execute);const end=new Date().toISOString();
 const report=Buffer.from(scan.stdout??''),stderr=Buffer.from(scan.stderr??'');fs.writeFileSync(path.join(root,'report.json'),report,{flag:'wx',mode:0o600});fs.writeFileSync(path.join(root,'stderr.log'),stderr,{flag:'wx',mode:0o600});
 if(scan.error||hashBounded(path.join(cache,'db/trivy.db'),2_000_000_000)!==database.sha256||sha256(readBounded(executable,10_000_000))!==BINARY)fail('SCAN_EXECUTION');
 const scanReceipt=validateActionlintScan({report,stderr,status:scan.status,binarySha256:BINARY,scannerSha256:SCANNER,startedAt:start,finishedAt:end,database,now:Date.now()},policy);
 fs.writeFileSync(path.join(root,'scan-receipt.json'),JSON.stringify({...scanReceipt,runIdentity:admitted.runIdentity,runtimeConfig:admitted.runtime.configId,executionImage:admitted.runtimeImage,sourceMounted:false,network:'none',credentialsPassed:false},null,2)+'\n',{flag:'wx',mode:0o600});
 const work=path.join(root,'workflows'),files=captureWorkflows(path.resolve(source),work);
 const result=run(admitted,[...containerArguments(admitted.runtimeImage,'/actionlint',[[executable,'/actionlint'],[work,'/work']]),'-shellcheck=','-pyflakes=','-oneline',...files.map(f=>'/work/'+f.path)],60000,execute);
 const projected=projectLinterOutput(result.stdout??'',result.stderr??''),outputSafe=projected.safe;
 fs.writeFileSync(path.join(root,'stdout.log'),projected.stdout,{flag:'wx',mode:0o600});fs.writeFileSync(path.join(root,'lint-stderr.log'),projected.stderr,{flag:'wx',mode:0o600});
 const receipt={status:!result.error&&result.status===0&&outputSafe?'PASS':'BLOCK',runIdentity:admitted.runIdentity,binarySha256:BINARY,executionImage:admitted.runtimeImage,runtimeConfig:admitted.runtime.configId,scanReceiptSha256:sha256(readBounded(path.join(root,'scan-receipt.json'),100000)),files,network:'none',credentialsPassed:false,timeout:!!result.error,outputSafe,exitCode:result.status,scope:policy.scope};fs.writeFileSync(path.join(root,'receipt.json'),JSON.stringify(receipt,null,2)+'\n',{flag:'wx',mode:0o600});if(receipt.status!=='PASS')fail('WORKFLOW_VALIDATION');return receipt;
}
if(process.argv[1]&&path.resolve(process.argv[1])===import.meta.filename){if(process.argv.length!==2)fail('ARGUMENTS');console.log(JSON.stringify(runActionlint()));}
