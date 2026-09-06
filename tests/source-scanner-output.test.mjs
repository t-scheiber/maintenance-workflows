import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const launcher=fileURLToPath(new URL('../tools/static-pages/source-scanner.mjs',import.meta.url));
const syntheticImage='sha256:'+'a'.repeat(64);
// Exercise actual data-plane launcher with synthetic scanner processes, without inventing native admission.
function driver(fixture,bin){const file=path.join(fixture,'driver.mjs');fs.writeFileSync(file,`import {scanSource} from ${JSON.stringify(new URL('../tools/static-pages/source-scanner.mjs',import.meta.url).href)};const scanner=process.argv[2];const result=scanSource(scanner,{runtimeImage:${JSON.stringify(syntheticImage)},executable:${JSON.stringify(bin)}+'/'+(scanner==='osv'?'osv-scanner':scanner),dockerCommand:${JSON.stringify(bin)}+'/docker',dockerEnvironment:{PATH:process.env.PATH}});if(!result.success)process.exitCode=1;`);return file;}
function exercise(t,kind,malformed=false){
 const fixture=fs.mkdtempSync(path.join(os.tmpdir(),'scanner-output-'));t.after(()=>fs.rmSync(fixture,{recursive:true,force:true}));
 const dirs=Object.fromEntries(['source','host-fixture','bin','temp'].map(name=>[name,path.join(fixture,name)]));for(const dir of Object.values(dirs))fs.mkdirSync(dir);
 const marker=path.join(dirs['host-fixture'],'synthetic-host-marker.txt');fs.writeFileSync(marker,'Synthetic host fixture only.\n');
 const outside=path.join(dirs['host-fixture'],'trivy.json');
 if(kind==='directory')fs.symlinkSync(dirs['host-fixture'],path.join(dirs.source,'pilot-results'));
 else{fs.mkdirSync(path.join(dirs.source,'pilot-results'));fs.symlinkSync(outside,path.join(dirs.source,'pilot-results/trivy.json'));}
 const report=malformed?{}:{SchemaVersion:2,ArtifactName:'/work',ArtifactType:'filesystem'};
 const fake=`#!${process.execPath}\nconst fs=require('fs'),args=process.argv.slice(2);if(args[0]==='run'){const mount=args.find(x=>x.startsWith('type=bind,src=')&&x.endsWith(',dst=/out'));if(!mount)process.exit(2);const out=mount.slice('type=bind,src='.length,-',dst=/out'.length);fs.writeFileSync(out+'/report.json',${JSON.stringify(JSON.stringify(report))});}\n`;
 fs.writeFileSync(path.join(dirs.bin,'docker'),fake,{mode:0o755});fs.writeFileSync(path.join(dirs.bin,'trivy'),'#!/bin/sh\nexit 0\n',{mode:0o755});
 const output=path.join(fixture,'github-output');fs.writeFileSync(output,'');
 const run=spawnSync(process.execPath,[driver(fixture,dirs.bin),'trivy'],{cwd:dirs.source,env:{PATH:dirs.bin+':'+path.dirname(process.execPath)+':/usr/bin:/bin',HOME:fixture,RUNNER_TEMP:dirs.temp,GITHUB_OUTPUT:output},encoding:'utf8',timeout:20000});
 assert.equal(run.status,malformed?1:0,run.stderr);
 assert.equal(fs.existsSync(outside),false);assert.equal(fs.readFileSync(marker,'utf8'),'Synthetic host fixture only.\n');
 const line=fs.readFileSync(output,'utf8').trim();assert.match(line,/^summary_path=/);const file=line.slice('summary_path='.length);
 assert.equal(path.dirname(path.dirname(file)),dirs.temp);assert.match(path.basename(path.dirname(file)),/^source-summary-/);
 const receipt=JSON.parse(fs.readFileSync(file));assert.equal(receipt.result,malformed?'failure':'success');
 assert.deepEqual(fs.readdirSync(path.dirname(file)),['trivy.json']);
 assert.ok(!fs.readFileSync(file,'utf8').includes('Synthetic host fixture'));
 return receipt;
}
test('source-owned report directory symlink cannot write outside source or enter uploaded summary',t=>exercise(t,'directory'));
test('source-owned report child symlink cannot receive scanner summary writes',t=>exercise(t,'child'));
test('failed scanner leaves a safe failure receipt in trusted temporary storage',t=>exercise(t,'directory',true));
test('security artifacts use the launcher exact trusted path, never repository-owned reports',()=>{
 const workflow=fs.readFileSync(new URL('../.github/workflows/static-pages.yml',import.meta.url),'utf8');
 assert.ok(workflow.includes('path: ${{ steps.scan.outputs.summary_path }}'));
 assert.ok(workflow.includes("if: always() && steps.scan.outputs.summary_path != ''"));
 assert.ok(!workflow.includes('source/pilot-results'));
});

for(const exists of [false,true])test(`scanner report ${exists?'existing':'dangling'} symlink is rejected without outside read or write`,t=>{
 const fixture=fs.mkdtempSync(path.join(os.tmpdir(),'scanner-raw-link-'));t.after(()=>fs.rmSync(fixture,{recursive:true,force:true}));
 const source=path.join(fixture,'source'),bin=path.join(fixture,'bin'),temp=path.join(fixture,'temp');for(const dir of [source,bin,temp])fs.mkdirSync(dir);
 const outside=path.join(fixture,'synthetic-host-file');if(exists)fs.writeFileSync(outside,'Synthetic host-only fixture.\n');
 const fake=`#!${process.execPath}\nconst fs=require('fs'),args=process.argv.slice(2);if(args[0]==='run'){const mount=args.find(x=>x.startsWith('type=bind,src=')&&x.endsWith(',dst=/out'));const out=mount.slice('type=bind,src='.length,-',dst=/out'.length);fs.symlinkSync(${JSON.stringify(outside)},out+'/report.json');}\n`;
 fs.writeFileSync(path.join(bin,'docker'),fake,{mode:0o755});fs.writeFileSync(path.join(bin,'trivy'),'#!/bin/sh\nexit 0\n',{mode:0o755});
 const output=path.join(fixture,'github-output');fs.writeFileSync(output,'');
 const run=spawnSync(process.execPath,[driver(fixture,bin),'trivy'],{cwd:source,env:{PATH:bin+':'+path.dirname(process.execPath)+':/usr/bin:/bin',HOME:fixture,RUNNER_TEMP:temp,GITHUB_OUTPUT:output},encoding:'utf8',timeout:20000});
 assert.equal(run.status,1);assert.match(run.stderr,/cannot be safely read/);
 assert.equal(fs.existsSync(outside),exists);if(exists)assert.equal(fs.readFileSync(outside,'utf8'),'Synthetic host-only fixture.\n');
 const file=fs.readFileSync(output,'utf8').trim().slice('summary_path='.length);const receipt=fs.readFileSync(file,'utf8');assert.equal(JSON.parse(receipt).result,'failure');assert.ok(!receipt.includes('Synthetic host-only fixture'));
});

for(const scanner of ['osv','trivy','gitleaks'])test(`${scanner} uses exact reviewed public transport with explicit scanner entrypoint`,t=>{
 const fixture=fs.mkdtempSync(path.join(os.tmpdir(),'scanner-transport-'));t.after(()=>fs.rmSync(fixture,{recursive:true,force:true}));
 const source=path.join(fixture,'source'),bin=path.join(fixture,'bin'),temp=path.join(fixture,'temp');for(const dir of [source,bin,temp])fs.mkdirSync(dir);fs.mkdirSync(path.join(source,'.git'));
 const report=scanner==='osv'?{results:[]}:scanner==='trivy'?{SchemaVersion:2,ArtifactName:'/work',ArtifactType:'filesystem'}:[];
 const capture=path.join(fixture,'args.json');
 const fake=`#!${process.execPath}\nconst fs=require('fs'),args=process.argv.slice(2);if(args[0]==='run'){fs.writeFileSync(${JSON.stringify(capture)},JSON.stringify(args));const mount=args.find(x=>x.startsWith('type=bind,src=')&&x.endsWith(',dst=/out'));const out=mount.slice('type=bind,src='.length,-',dst=/out'.length);fs.writeFileSync(out+'/report.json',${JSON.stringify(JSON.stringify(report))});}\n`;
 fs.writeFileSync(path.join(bin,'docker'),fake,{mode:0o755});fs.writeFileSync(path.join(bin,scanner==='osv'?'osv-scanner':scanner),'#!/bin/sh\nexit 0\n',{mode:0o755});
 const run=spawnSync(process.execPath,[driver(fixture,bin),scanner],{cwd:source,env:{PATH:bin+':'+path.dirname(process.execPath)+':/usr/bin:/bin',HOME:fixture,RUNNER_TEMP:temp},encoding:'utf8',timeout:20000});assert.equal(run.status,0,run.stderr);
 const args=JSON.parse(fs.readFileSync(capture));const runtime=JSON.parse(fs.readFileSync(new URL('../tools/static-pages/runtime.json',import.meta.url)));
 assert.equal(args[args.indexOf('--entrypoint')+1],'/scanner');assert.equal(args.filter(x=>x==='--entrypoint').length,1);
 const index=args.indexOf(syntheticImage);assert.ok(index>0);assert.equal(args[index+1],scanner==='osv'?'scan':scanner==='trivy'?'fs':'git');
 assert.equal(args[args.indexOf('--network')+1],scanner==='gitleaks'?'none':'bridge');
 assert.ok(args.some(x=>x.endsWith(',dst=/scanner,readonly')));
 if(scanner==='gitleaks'){assert.ok(args.includes('--log-opts=--all'));assert.ok(args.includes('/history'));}
});

test('actual OSV exit128 cannot erase findings or analysis errors in a dependency-free source',t=>{
 for(const report of [{},{results:[]},{results:[{packages:[{vulnerabilities:[{id:'CVE-2026-1234'}]}]}]},{errors:['synthetic incomplete analysis']}]){
  const fixture=fs.mkdtempSync(path.join(os.tmpdir(),'scanner-osv128-'));t.after(()=>fs.rmSync(fixture,{recursive:true,force:true}));
  const source=path.join(fixture,'source'),bin=path.join(fixture,'bin'),temp=path.join(fixture,'temp');for(const dir of [source,bin,temp])fs.mkdirSync(dir);fs.writeFileSync(path.join(source,'package.json'),'{}');
  const fake=`#!${process.execPath}\nconst fs=require('fs'),args=process.argv.slice(2);if(args[0]==='run'){const mount=args.find(x=>x.startsWith('type=bind,src=')&&x.endsWith(',dst=/out'));const out=mount.slice('type=bind,src='.length,-',dst=/out'.length);fs.writeFileSync(out+'/report.json',${JSON.stringify(JSON.stringify(report))});process.exit(128);}\n`;
  fs.writeFileSync(path.join(bin,'docker'),fake,{mode:0o755});fs.writeFileSync(path.join(bin,'osv-scanner'),'#!/bin/sh\nexit 0\n',{mode:0o755});
  const output=path.join(fixture,'github-output');fs.writeFileSync(output,'');
  const run=spawnSync(process.execPath,[driver(fixture,bin),'osv'],{cwd:source,env:{PATH:bin+':'+path.dirname(process.execPath)+':/usr/bin:/bin',HOME:fixture,RUNNER_TEMP:temp,GITHUB_OUTPUT:output},encoding:'utf8',timeout:20000});
  const blocking=Boolean(report.results?.length||report.errors);assert.equal(run.status,blocking?1:0);
  const file=fs.readFileSync(output,'utf8').trim().slice('summary_path='.length);assert.equal(JSON.parse(fs.readFileSync(file)).result,blocking?'failure':'success');
 }
});

// A scanner may create a FIFO instead of its declared JSON report. Never block opening it.
test('scanner-controlled FIFO report is rejected promptly',t=>{
 const fixture=fs.mkdtempSync(path.join(os.tmpdir(),'scanner-raw-fifo-'));t.after(()=>fs.rmSync(fixture,{recursive:true,force:true}));
 const source=path.join(fixture,'source'),bin=path.join(fixture,'bin'),temp=path.join(fixture,'temp');for(const dir of [source,bin,temp])fs.mkdirSync(dir);
 const fake=`#!${process.execPath}\nconst {spawnSync}=require('child_process'),args=process.argv.slice(2);if(args[0]==='run'){const mount=args.find(x=>x.startsWith('type=bind,src=')&&x.endsWith(',dst=/out'));const out=mount.slice('type=bind,src='.length,-',dst=/out'.length);if(spawnSync('/usr/bin/mkfifo',[out+'/report.json']).status!==0)process.exit(2);}`;
 fs.writeFileSync(path.join(bin,'docker'),fake,{mode:0o755});fs.writeFileSync(path.join(bin,'trivy'),'#!/bin/sh\nexit 0\n',{mode:0o755});
 const run=spawnSync(process.execPath,[driver(fixture,bin),'trivy'],{cwd:source,env:{PATH:bin+':'+path.dirname(process.execPath)+':/usr/bin:/bin',HOME:fixture,RUNNER_TEMP:temp},encoding:'utf8',timeout:5000});
 assert.equal(run.error,undefined);assert.equal(run.status,1);assert.match(run.stderr,/cannot be safely read/);
});

test('actual public scanner CLI rejects missing native evidence before any source processing',t=>{
 const fixture=fs.mkdtempSync(path.join(os.tmpdir(),'source-cli-pending-'));t.after(()=>fs.rmSync(fixture,{recursive:true,force:true}));
 const source=path.join(fixture,'source'),temp=path.join(fixture,'temp');fs.mkdirSync(source);fs.mkdirSync(temp);
 fs.symlinkSync('/synthetic/nonexistent',path.join(source,'pilot-results'));
 const env={PATH:'/usr/bin:/bin',RUNNER_TEMP:temp,GITHUB_REPOSITORY:'t-scheiber/maintenance-workflows',GITHUB_REPOSITORY_ID:'1359178236',GITHUB_REPOSITORY_OWNER_ID:'66697291',PUBLIC_REPOSITORY_PRIVATE:'false',GITHUB_RUN_ID:'123',GITHUB_RUN_ATTEMPT:'1',GITHUB_SHA:'a'.repeat(40),PUBLIC_TOOLS_REF:'b'.repeat(40)};
 const run=spawnSync(process.execPath,[launcher,'trivy'],{cwd:source,env,encoding:'utf8',timeout:3000});
 assert.equal(run.status,1);assert.match(run.stderr,/FILE_|ENOENT/);assert.deepEqual(fs.readdirSync(temp),[]);assert.equal(run.stdout,'');
});
