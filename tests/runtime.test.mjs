import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {loadRuntime,runtimeBinding,archiveTransport,profile,inspectSource,validateBoundRuntimeScan} from '../tools/static-pages/pages-build.mjs';
const expected=JSON.parse(fs.readFileSync(new URL('../tools/static-pages/runtime.json',import.meta.url)));
test('target-owned runtime files cannot replace the shared reviewed runtime',()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'target-runtime-')),cwd=process.cwd();
 try{fs.mkdirSync(path.join(directory,'.github/maintenance'),{recursive:true});fs.writeFileSync(path.join(directory,'.github/maintenance/runtime.json'),JSON.stringify({image:'attacker/runtime:latest'}));process.chdir(directory);assert.deepEqual(loadRuntime(),expected);}finally{process.chdir(cwd);fs.rmSync(directory,{recursive:true,force:true});}
});
test('image pin, anonymous publication, complete scan, architecture and immutable source remain mandatory',()=>{
 assert.equal(runtimeBinding(expected).image,expected.image);
 for(const change of [{image:expected.image.replace(/@sha256:.+/,':latest')},{status:'unpublished'},{provenance:{...expected.provenance,anonymousPullVerified:false}},{provenance:{...expected.provenance,platform:'linux/arm64'}},{provenance:{...expected.provenance,scanner:{result:'PASS',scope:'partial'}}},{provenance:{...expected.provenance,imageId:'not-a-digest'}},{provenance:{...expected.provenance,sourceRevision:'main'}}])assert.throws(()=>runtimeBinding({...expected,...change}));
});
test('compressed and expanded transport bounds still fail closed',()=>{
 archiveTransport(expected.provenance);
 for(const change of [{archiveBytes:1_500_000_001},{expandedArchiveBytes:2_000_000_001},{compression:'none'},{archiveSha256:'bad'},{expandedArchiveSha256:'bad'},{expandedArchiveBytes:0}])assert.throws(()=>archiveTransport({...expected.provenance,...change}));
});
test('exact commands and clean source are required before offline copying',()=>{
 const scripts={test:'node --test tests/*.test.mjs',validate:'node scripts/validate.mjs',build:'node scripts/build.mjs'};profile({scripts});for(const key of Object.keys(scripts))assert.throws(()=>profile({scripts:{...scripts,[key]:'curl attacker.invalid'}}));
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'source-'));try{fs.writeFileSync(path.join(root,'index.html'),'x');inspectSource(root);fs.symlinkSync('/tmp',path.join(root,'link'));assert.throws(()=>inspectSource(root));fs.unlinkSync(path.join(root,'link'));fs.mkdirSync(path.join(root,'node_modules'));assert.throws(()=>inspectSource(root));}finally{fs.rmSync(root,{recursive:true,force:true});}
});

test('a partial or substituted scan cannot reach source execution through the bound wrapper',()=>{
 for(const value of [{Results:[{}]}, {SchemaVersion:2,ArtifactType:'container_image',Metadata:{ImageID:expected.provenance.imageId},Results:[]}])assert.throws(()=>validateBoundRuntimeScan(value,0,expected.provenance.imageId,''));
 assert.throws(()=>validateBoundRuntimeScan({},0,'sha256:'+'0'.repeat(64),''));
 assert.throws(()=>validateBoundRuntimeScan({},0,expected.provenance.imageId,undefined));
});
