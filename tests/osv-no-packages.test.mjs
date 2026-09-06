// SPDX-License-Identifier: MIT
import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import os from 'node:os';import path from 'node:path';
import {assertDependencyFreeSource} from '../tools/static-pages/osv-no-packages.mjs';
function fixture(t,files={}){const root=fs.mkdtempSync(path.join(os.tmpdir(),'osv-empty-test-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));for(const [name,value] of Object.entries({'package.json':{name:'root',private:true},...files})){const file=path.join(root,name);fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,typeof value==='string'?value:JSON.stringify(value));}return root;}
test('truly dependency-free Node root with an empty npm lock permits OSV no-packages',t=>{
 const source=fixture(t,{'package-lock.json':{lockfileVersion:3,packages:{'':{name:'root'}}},'app/package.json':{name:'empty-app'},'app/package-lock.json':{lockfileVersion:3,packages:{'':{name:'empty-app'}}}});
 assert.deepEqual(assertDependencyFreeSource(source),{dependencyFree:true,manifests:['app/package-lock.json','app/package.json','package-lock.json','package.json']});
});
test('Empty root with any nested npm dependency cannot pass exit128',t=>{
 for(const field of ['dependencies','devDependencies','optionalDependencies','peerDependencies'])assert.throws(()=>assertDependencyFreeSource(fixture(t,{'firstapp/package.json':{name:'firstapp',[field]:{react:'19.2.7'}},'secondapp/package.json':{},'thirdapp/package.json':{}})),/dependency/);
 for(const file of ['package-lock.json','npm-shrinkwrap.json'])assert.throws(()=>assertDependencyFreeSource(fixture(t,{[`thirdapp/${file}`]:{lockfileVersion:3,packages:{'':{},'node_modules/react':{version:'19.2.7'}}}})),/locked dependency/);
});
test('root-only, legacy-lock and root-in-lock dependency graphs all fail no-packages',t=>{
 for(const files of [{'package.json':{dependencies:{x:'1'}}},{'nested/package-lock.json':{lockfileVersion:1,dependencies:{x:{version:'1'}}}},{'nested/package-lock.json':{lockfileVersion:3,packages:{'':{dependencies:{x:'1'}}}}},{'nested/package.json':{workspaces:['app']}},{'nested/package.json':{bundledDependencies:['x']}}])assert.throws(()=>assertDependencyFreeSource(fixture(t,files)),/dependency/);
});
test('malformed manifests, other manager files and unsafe sources fail closed',t=>{
 for(const value of ['{',null,[],{dependencies:[]},{dependencies:'x'}])assert.throws(()=>assertDependencyFreeSource(fixture(t,{'nested/package.json':value})));
 for(const value of [{},{lockfileVersion:3},{lockfileVersion:9},{lockfileVersion:3,packages:[]},{lockfileVersion:3,packages:{'':[]}}])assert.throws(()=>assertDependencyFreeSource(fixture(t,{'nested/package-lock.json':value})));
 for(const file of ['requirements.txt','pyproject.toml','Cargo.lock','go.mod','pom.xml','build.gradle.kts','project.csproj','pnpm-lock.yaml','yarn.lock','bun.lock','bun.lockb','deno.lock'])assert.throws(()=>assertDependencyFreeSource(fixture(t,{[`app/${file}`]:''})),/dependency manifest/);
 const linked=fixture(t);fs.symlinkSync('/dev/null',path.join(linked,'package-lock.json'));assert.throws(()=>assertDependencyFreeSource(linked));
 const large=fixture(t,{'nested/package.json':' '.repeat(2000001)});assert.throws(()=>assertDependencyFreeSource(large),/bounds/);
 const missing=fixture(t);fs.unlinkSync(path.join(missing,'package.json'));assert.throws(()=>assertDependencyFreeSource(missing),/Missing/);
});
test('pilot OSV fallback always applies full snapshot proof before accepting exit128',()=>{
 const code=fs.readFileSync(new URL('../tools/static-pages/source-scanner.mjs',import.meta.url),'utf8');
 assert.match(code,/if\(scanner==='osv'&&status===128\)\{\s*assertNoPackagesReport\(data\);\s*assertDependencyFreeSource\(source\);/);assert.match(code,/!run.error/);assert.match(code,/Complete Git history is required/);
});

test('OSV no-package status never overrides nonempty findings or an error report',async()=>{
 const {assertNoPackagesReport}=await import('../tools/static-pages/osv-no-packages.mjs');
 for(const value of [null,{}, {results:[]},{results:[],experimental_config:{}}])assert.doesNotThrow(()=>assertNoPackagesReport(value));
 for(const value of [[],{results:[{packages:[{vulnerabilities:[{id:'CVE-2026-1234'}]}]}]},{results:{}},{errors:['incomplete']},{unexpected:true},''])assert.throws(()=>assertNoPackagesReport(value));
});
