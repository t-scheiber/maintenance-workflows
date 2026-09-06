import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {loadNativeEvidence} from '../tools/native/native-evidence.mjs';
import {sha256,LIMITS} from '../tools/native/native-admission.mjs';
const fields=['report','stderr','graph','manifest','buildInfo','pclntab','advisory','execution','provenance','binary'];
function setup(t){const root=fs.mkdtempSync(path.join(os.tmpdir(),'native-evidence-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));const files=Object.fromEntries(fields.map(k=>[k,k]));for(const k of fields)fs.writeFileSync(path.join(root,k),k==='binary'?Buffer.alloc(2048,7):'{}',{mode:k==='binary'?0o755:0o644});return {root,files};}
test('file adapter captures bounded immutable bytes without executing the binary',t=>{const {root,files}=setup(t),r=loadNativeEvidence(root,files);assert.equal(r.binary.sha256,sha256(Buffer.alloc(2048,7)));assert.equal(r.binary.mode,493);assert.equal(r.report.toString(),'{}');});
for(const [name,edit] of [
 ['parent path escape',(x)=>x.files.report='../outside'],
 ['absolute path',(x)=>x.files.report='/etc/passwd'],
 ['unknown evidence field',(x)=>x.files.extra='report'],
 ['missing evidence',(x)=>fs.unlinkSync(path.join(x.root,'report'))],
 ['directory instead of report',(x)=>{fs.unlinkSync(path.join(x.root,'report'));fs.mkdirSync(path.join(x.root,'report'));}],
 ['dangling report symlink',(x)=>{fs.unlinkSync(path.join(x.root,'report'));fs.symlinkSync('/synthetic/nonexistent',path.join(x.root,'report'));}],
 ['existing report symlink',(x)=>{fs.unlinkSync(path.join(x.root,'report'));fs.symlinkSync(path.join(x.root,'stderr'),path.join(x.root,'report'));}],
 ['ancestor directory symlink',(x)=>{fs.symlinkSync(x.root,path.join(x.root,'linked'));x.files.report='linked/report';}],
 ['nonexecutable binary',(x)=>fs.chmodSync(path.join(x.root,'binary'),0o644)],
 ['oversized report',(x)=>fs.truncateSync(path.join(x.root,'report'),LIMITS.report+1)],
 ['empty report',(x)=>fs.truncateSync(path.join(x.root,'report'),0)],
])test(name,t=>{const x=setup(t);edit(x);assert.throws(()=>loadNativeEvidence(x.root,x.files),e=>e.message.startsWith('Native scanner admission rejected:'));});
test('actual FIFO rejects promptly in a bounded child before any blocking read',t=>{const {root,files}=setup(t);fs.unlinkSync(path.join(root,'report'));const made=spawnSync('mkfifo',[path.join(root,'report')],{timeout:1000});assert.equal(made.status,0);const module=new URL('../tools/native/native-evidence.mjs',import.meta.url).href;const child=spawnSync(process.execPath,['--input-type=module','-e',`import {loadNativeEvidence} from ${JSON.stringify(module)}; try {loadNativeEvidence(${JSON.stringify(root)},${JSON.stringify(files)});process.exit(2)}catch(e){if(!e.message.startsWith('Native scanner admission rejected:'))process.exit(3);process.exit(0)}`],{timeout:2000,encoding:'utf8'});assert.equal(child.error,undefined);assert.equal(child.status,0);assert.equal(child.stdout,'');});
test('regular file replaced by FIFO between lstat and open cannot block the adapter',t=>{const {root,files}=setup(t);const module=new URL('../tools/native/native-evidence.mjs',import.meta.url).href;const code=`import fs from 'node:fs';import {spawnSync} from 'node:child_process';import {loadNativeEvidence} from ${JSON.stringify(module)};const original=fs.openSync;let replaced=false;fs.openSync=function(file,flags,...rest){if(file===${JSON.stringify(path.join(root,'report'))}&&!replaced){replaced=true;fs.unlinkSync(file);if(spawnSync('mkfifo',[file],{timeout:1000}).status!==0)process.exit(3);}return original.call(fs,file,flags,...rest)};try{loadNativeEvidence(${JSON.stringify(root)},${JSON.stringify(files)});process.exit(2)}catch(e){process.exit(replaced&&e.code==='FILE_BOUNDS'?0:4)}`;const child=spawnSync(process.execPath,['--input-type=module','-e',code],{timeout:3000,encoding:'utf8'});assert.equal(child.error,undefined);assert.equal(child.status,0);});
