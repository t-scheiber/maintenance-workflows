// SPDX-License-Identifier: MIT
// Trusted launcher. Target source and scanner execution stay inside a disposable container.
import fs from 'node:fs';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {gitleaksConfig} from './secret-patterns.mjs';
import {sourceFindings} from './scanner-results.mjs';
import {assertDependencyFreeSource,assertNoPackagesReport} from './osv-no-packages.mjs';
import {preparedScanner} from './prepared-scanners.mjs';
import {spawnSync} from 'node:child_process';
export function scanSource(scanner,{runtimeImage,executable,dockerCommand,dockerEnvironment,sourceDirectory=process.cwd(),env=process.env}={}){
if(typeof runtimeImage!=='string'||!/^sha256:[a-f0-9]{64}$/.test(runtimeImage))throw Error('Verified immutable execution image required');
if(!['osv','gitleaks','trivy','semgrep'].includes(scanner))throw Error('Unknown scanner');
if(typeof dockerCommand!=='string'||!path.isAbsolute(dockerCommand)||!dockerEnvironment||typeof dockerEnvironment.PATH!=='string'||Object.keys(dockerEnvironment).some(key=>!['PATH','DOCKER_CONFIG','DOCKER_HOST'].includes(key)))throw Error('Trusted Docker transport required');
const source=path.resolve(sourceDirectory);
const history=scanner==='gitleaks'?path.join(source,'.git'):null;
if(history&&!fs.existsSync(history))throw Error('Complete Git history is required');
const output=fs.mkdtempSync(path.join(env.RUNNER_TEMP,'pilot-scan-'));
// This directory is never mounted into a scanner or source container.
const summaries=fs.mkdtempSync(path.join(env.RUNNER_TEMP,'source-summary-'));
const summaryFile=path.join(summaries,scanner+'.json');
fs.writeFileSync(summaryFile,JSON.stringify({scanner,result:'failure',reason:'Scanner did not complete'}),{mode:0o600,flag:'wx'});
if(env.GITHUB_OUTPUT)fs.appendFileSync(env.GITHUB_OUTPUT,`summary_path=${summaryFile}\n`);
const image=runtimeImage;
fs.writeFileSync(path.join(output,'ignore'),'');
fs.writeFileSync(path.join(output,'gitleaks.toml'),gitleaksConfig());
fs.writeFileSync(path.join(output,'trivy.yaml'),'{}\n');
fs.writeFileSync(path.join(output,'osv.toml'),'\n');
const network=scanner==='gitleaks'?'none':'bridge';
const containerName='public-source-scan-'+randomUUID();
const args=['run','--name',containerName,'--platform','linux/amd64','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','256','--cpus','2','--memory','3g','--network',network,'--user',`${process.getuid()}:${process.getgid()}`,'--tmpfs','/tmp:rw,nosuid,nodev,size=1g','--mount',`type=bind,src=${source},dst=/work,readonly`,'--mount',`type=bind,src=${output},dst=/out`,'--workdir','/tmp','--env','HOME=/tmp'];
args.push('--mount','type=bind,src=/etc/ssl/certs/ca-certificates.crt,dst=/etc/ssl/certs/ca-certificates.crt,readonly');
if(history)args.push('--mount',`type=bind,src=${history},dst=/history,readonly`,'--env','GIT_CONFIG_NOSYSTEM=1','--env','GIT_CONFIG_GLOBAL=/dev/null');
let command;
if(scanner==='semgrep'){
  args.push('--entrypoint','semgrep');
  command=['scan','--config','p/security-audit','--config','p/owasp-top-ten','--metrics','off','--disable-version-check','--disable-nosem','--no-git-ignore','--x-ignore-semgrepignore-files','--exclude','.git','--error','--json','--output','/out/report.json','/work'];
}else{
  if(typeof executable!=='string'||!path.isAbsolute(executable))throw Error('Admitted scanner executable required');
  args.push('--mount',`type=bind,src=${executable},dst=/scanner,readonly`,'--entrypoint','/scanner');
  if(scanner==='osv')command=['/scanner','scan','source','-r','--config=/out/osv.toml','--format=json','--output=/out/report.json','/work'];
  if(scanner==='trivy')command=['/scanner','fs','--config','/out/trivy.yaml','--ignorefile','/out/ignore','--cache-dir','/tmp/trivy','--scanners','misconfig','--severity','HIGH,CRITICAL','--exit-code','1','--format','json','--output','/out/report.json','/work'];
  if(scanner==='gitleaks')command=['/scanner',history?'git':'dir',...(history?['--log-opts=--all']:[]),'--config','/out/gitleaks.toml','--ignore-gitleaks-allow','--gitleaks-ignore-path','/out/ignore','--redact=100','--report-format','json','--report-path','/out/report.json','--exit-code','1',history?'/history':'/work'];
}
let run;
try{run=spawnSync(dockerCommand,[...args,image,...(scanner==='semgrep'?command:command.slice(1))],{env:dockerEnvironment,encoding:'utf8',timeout:600000,maxBuffer:16*1024*1024});}
finally{const cleanup=spawnSync(dockerCommand,['rm','-f',containerName],{env:dockerEnvironment,encoding:'utf8',timeout:30000,maxBuffer:100000});if(cleanup.error||cleanup.status!==0)throw Error('Scanner container cleanup failed');}
// Scanner output can contain target-controlled strings. Never echo its stdout/stderr to the workflow log.
const filename=path.join(output,'report.json');
let raw='',descriptor;
try{
  descriptor=fs.openSync(filename,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  const stat=fs.fstatSync(descriptor);
  if(!stat.isFile()||stat.size>16*1024*1024)throw Error('Scanner report missing or oversized');
  raw=fs.readFileSync(descriptor,'utf8');
}catch(error){if(error.code!=='ENOENT')throw Error('Scanner report cannot be safely read');}
finally{if(descriptor!==undefined)fs.closeSync(descriptor);}
// Unlink acts on the directory entry itself and cannot write through a scanner-controlled link.
function discardReport(){try{fs.unlinkSync(filename);}catch(error){if(error.code!=='ENOENT')throw Error('Scanner report cannot be safely removed');}}
let data;
try{data=raw.trim()?JSON.parse(raw):null;}catch{discardReport();throw Error(`${scanner} produced invalid JSON`);}
const status=run.status;
let findings=[];
if(scanner==='osv'&&status===128){
  assertNoPackagesReport(data);
  assertDependencyFreeSource(source);
  console.log('OSV executed; the complete bounded source snapshot is dependency-free. Container dependencies require the separate image scan.');
}else{
  try{findings=sourceFindings(scanner,data);}catch{
    // Do not preserve or log malformed payload fields, which may contain source or credentials.
    discardReport();
    throw Error('Scanner report is malformed, incomplete or contains unsafe locations');
  }
  if(scanner==='gitleaks')discardReport();
}
const success=findings.length===0&&!run.error&&(status===0||(scanner==='osv'&&status===128));
const summary={scanner,result:success?'success':'failure',exitCode:status,findings,...(scanner==='gitleaks'?{scope:history?'complete-default-and-pr-history':'source-snapshot'}:{})};
fs.writeFileSync(summaryFile,JSON.stringify(summary),{mode:0o600});
console.log(JSON.stringify(summary));
if(env.GITHUB_STEP_SUMMARY)fs.appendFileSync(env.GITHUB_STEP_SUMMARY,`${scanner}: ${summary.result}; ${findings.length} blocking findings\n`);
return {success,summary};
}
if(process.argv[1]&&path.resolve(process.argv[1])===import.meta.filename){
 if(process.argv.length!==3)throw Error('Exactly one scanner required');
 const scanner=process.argv[2],admitted=preparedScanner(scanner);
 const result=scanSource(scanner,admitted);if(!result.success)process.exitCode=1;
}
