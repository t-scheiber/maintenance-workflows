// SPDX-License-Identifier: MIT
// Lockfiles are data. Only hashed npm registry artifacts enter the networked install phase.
import {isDeepStrictEqual} from 'node:util';
const name=/^(?:@[a-z0-9_.-]+\/)?[a-z0-9_.-]+$/i;
const dictionary=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
// npm/node-semver range.bnf: numeric or wildcard components, then optional
// prerelease/build identifiers on a complete three-component version. Validate
// each bounded comparator separately, without interpreting or rewriting ranges.
const numeric='(?:0|[1-9][0-9]*)';
const component=`(?:${numeric}|[xX*])`;
const prerelease=`(?:${numeric}|[0-9]*[A-Za-z-][0-9A-Za-z-]*)`;
const qualifier=`(?:-${prerelease}(?:\\.${prerelease})*)?(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?`;
const partial=new RegExp(`^${component}(?:\\.${component}(?:\\.${component}${qualifier})?)?$`);
const exact=new RegExp(`^${numeric}\\.${numeric}\\.${numeric}${qualifier}$`);
function boundedVersion(value,pattern) {
  if(!pattern.test(value))return false;
  const core=value.split(/[-+]/,1)[0].split('.');
  return core.every(part=>/^[xX*]$/.test(part)||Number.isSafeInteger(Number(part)));
}
export function npmRegistryRange(value,maxLength=200) {
  if(![100,200].includes(maxLength)||typeof value!=='string'||!value.length||value.length>maxLength||/[^0-9A-Za-z.*~^<>=| +\-]/.test(value))return false;
  return value.split('||').every(arm=>{
    const trimmed=arm.trim();if(!trimmed)return false;
    const tokens=trimmed.split(/ +/);
    if(tokens.includes('-'))return tokens.length===3&&tokens[1]==='-'&&boundedVersion(tokens[0],partial)&&boundedVersion(tokens[2],partial);
    for(let i=0;i<tokens.length;i++) {
      const token=tokens[i];
      if(/^(?:<=|>=|[~^<>=])$/.test(token)) {
        if(++i===tokens.length||!boundedVersion(tokens[i],partial))return false;
      } else {
        const match=/^(?:<=|>=|[~^<>=])?(.+)$/.exec(token);
        if(!match||!boundedVersion(match[1],partial))return false;
      }
    }
    return true;
  });
}
const exactVersion=value=>typeof value==='string'&&value.length<=200&&boundedVersion(value,exact);
export function npmManifestInput(manifestText) {
  if(typeof manifestText!=='string'||Buffer.byteLength(manifestText)>2*1024*1024)throw Error('Manifest too large');
  const original=JSON.parse(manifestText);
  if(!dictionary(original)||!name.test(original.name||'')||['workspaces','overrides','resolutions','catalog','catalogs','patchedDependencies','peerDependencies'].some(k=>Object.hasOwn(original,k)))throw Error('Unsupported npm manifest layout');
  const sanitized={name:original.name};
  for(const field of ['dependencies','devDependencies','optionalDependencies']) {
    const dependencies=original[field]??{};
    if(!dictionary(dependencies)||Object.keys(dependencies).length>300)throw Error('Invalid direct dependencies');
    for(const [key,value] of Object.entries(dependencies))if(!name.test(key)||!npmRegistryRange(value,100))throw Error('Only registry version ranges are allowed');
    if(Object.hasOwn(original,field))sanitized[field]=dependencies;
  }
  if(original.version!==undefined){if(!exactVersion(original.version))throw Error('Invalid root version');sanitized.version=original.version;}
  if(original.engines!==undefined) {
    if(!dictionary(original.engines)||Object.entries(original.engines).some(([key,value])=>!['node','npm'].includes(key)||!npmRegistryRange(value,100)))throw Error('Unsupported declared npm runtime');
    sanitized.engines=original.engines;
  }
  return JSON.stringify(sanitized);
}
export function npmInstallationInputs(manifestText,lockText) {
  const sanitized=JSON.parse(npmManifestInput(manifestText));
  if(typeof lockText!=='string'||Buffer.byteLength(lockText)>2*1024*1024)throw Error('npm lockfile exceeds budget');
  const lock=JSON.parse(lockText);
  if(!dictionary(lock)||![2,3].includes(lock.lockfileVersion)||!dictionary(lock.packages)||!dictionary(lock.packages[''])||Object.keys(lock.packages).length>4000||Object.keys(lock).some(k=>!['name','version','lockfileVersion','requires','packages','dependencies'].includes(k)))throw Error('Unsupported npm lockfile layout');
  if(lock.name!==sanitized.name||lock.packages[''].name!==sanitized.name)throw Error('npm root identity mismatch');
  for(const field of ['dependencies','devDependencies','optionalDependencies'])if(!isDeepStrictEqual(sanitized[field]||{},lock.packages[''][field]||{}))throw Error('npm manifest and frozen lockfile disagree');
  const cleanPackages={'':sanitized};let count=0;
  for(const [location,entry] of Object.entries(lock.packages)) {
    if(location==='')continue;
    if(!/^(?:node_modules\/(?:@[a-z0-9_.-]+\/)?[a-z0-9_.-]+)(?:\/node_modules\/(?:@[a-z0-9_.-]+\/)?[a-z0-9_.-]+)*$/i.test(location)||location.split('/').some(p=>p==='.'||p==='..')||!dictionary(entry)||entry.link||entry.inBundle||entry.hasShrinkwrap||!exactVersion(entry.version))throw Error('Unsupported linked, bundled or unpinned npm package');
    const packageName=location.slice(location.lastIndexOf('node_modules/')+13);
    if(!name.test(packageName)||entry.name&&entry.name!==packageName)throw Error('npm package identity mismatch');
    const tarballName=packageName.split('/').at(-1);
    const expected=`https://registry.npmjs.org/${packageName}/-/${tarballName}-${entry.version}.tgz`;
    if(entry.resolved!==expected||!/^sha512-[A-Za-z0-9+/]{86}==$/.test(entry.integrity||''))throw Error('Only exact integrity-pinned npm registry artifacts are supported');
    for(const field of ['dependencies','optionalDependencies','peerDependencies']) {
      const values=entry[field]||{};
      if(!dictionary(values)||Object.entries(values).some(([key,value])=>!name.test(key)||!npmRegistryRange(value)))throw Error('External or local npm dependency reference rejected');
    }
    if(entry.bin!==undefined) {
      const paths=typeof entry.bin==='string'?[entry.bin]:dictionary(entry.bin)?Object.values(entry.bin):[null];
      if(paths.some(p=>typeof p!=='string'||p.startsWith('/')||p.includes('\\')||p.split('/').includes('..')))throw Error('npm executable path escapes package');
    }
    cleanPackages[location]=entry;count++;
  }
  // v2's compatibility graph is not needed by the pinned npm 12 client. Its canonical
  // package graph remains unchanged; project source and configuration are not mounted.
  const cleanLock={name:sanitized.name,...(sanitized.version?{version:sanitized.version}:{}),lockfileVersion:3,requires:true,packages:cleanPackages};
  return {manifest:JSON.stringify(sanitized),lock:JSON.stringify(cleanLock),packages:count};
}
