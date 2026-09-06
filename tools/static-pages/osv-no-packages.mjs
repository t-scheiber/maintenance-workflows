// SPDX-License-Identifier: MIT
// OSV exit 128 is exceptional: prove the complete admitted snapshot has no package graph.
import fs from 'node:fs';
import path from 'node:path';
import {inspectSource} from './pages-build.mjs';
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
function json(file){const value=JSON.parse(fs.readFileSync(file,'utf8'));if(!object(value))throw Error('Invalid dependency manifest');return value;}
function dependencies(value){
 for(const field of ['dependencies','devDependencies','optionalDependencies','peerDependencies']){
  if(value[field]!==undefined&&(!object(value[field])||Object.keys(value[field]).length))throw Error('OSV found no packages despite dependency manifests');
 }
 for(const field of ['bundledDependencies','bundleDependencies','workspaces'])if(value[field]!==undefined&&(!Array.isArray(value[field])||value[field].length))throw Error('OSV found no packages despite dependency graph declarations');
}
export function assertDependencyFreeSource(source){
 inspectSource(source);
 const manifests=[];let root=false;
 function walk(directory){for(const entry of fs.readdirSync(directory,{withFileTypes:true})){
  if(directory===source&&entry.name==='.git')continue;
  const file=path.join(directory,entry.name);
  if(entry.isDirectory()){walk(file);continue;}
  const name=entry.name;
  if(name==='package.json'){
   dependencies(json(file));manifests.push(path.relative(source,file));if(directory===source)root=true;
  }else if(name==='package-lock.json'||name==='npm-shrinkwrap.json'){
   const lock=json(file);dependencies(lock);
   if(![1,2,3].includes(lock.lockfileVersion))throw Error('Unsupported dependency lock schema');
   if(lock.lockfileVersion>=2&&(!object(lock.packages)||!object(lock.packages[''])))throw Error('Incomplete npm lock package graph');
   if(lock.packages!==undefined){if(!object(lock.packages)||Object.keys(lock.packages).some(key=>key!==''))throw Error('OSV found no packages despite locked dependency graph');if(lock.packages['']!==undefined){if(!object(lock.packages['']))throw Error('Invalid locked root package');dependencies(lock.packages['']);}}
   manifests.push(path.relative(source,file));
  }else if(/^(?:requirements.*\.txt|pyproject\.toml|Pipfile(?:\.lock)?|uv\.lock|poetry\.lock|Cargo\.(?:toml|lock)|go\.(?:mod|sum)|pom\.xml|build\.gradle(?:\.kts)?|composer\.(?:json|lock)|.+\.csproj|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|deno\.(?:jsonc?|lock))$/.test(name))throw Error('OSV found no packages despite another dependency manifest');
 }}
 walk(source);if(!root)throw Error('Missing dependency-free root Node manifest');
 return {dependencyFree:true,manifests:manifests.sort()};
}

// No-package status never overrides a nonempty or malformed vulnerability report.
export function assertNoPackagesReport(data){
 if(data===null)return;
 if(!data||typeof data!=='object'||Array.isArray(data))throw Error('Unexpected OSV no-package report');
 const keys=Object.keys(data);
 if(keys.length===0)return;
 if(keys.some(k=>!['results','experimental_config'].includes(k))||!Array.isArray(data.results)||data.results.length)throw Error('Unexpected OSV no-package report');
}
