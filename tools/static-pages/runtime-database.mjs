// SPDX-License-Identifier: MIT
// Reuse only the exact database already bound by native admission in this run.
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {parseJson} from '../native/native-admission.mjs';
const fail=()=>{throw Error('Runtime native database binding differs or expired');};
function open(file){
 const resolved=path.resolve(file);let parent=path.parse(resolved).root;
 for(const part of resolved.slice(parent.length).split('/').slice(0,-1)){parent=path.join(parent,part);const stat=fs.lstatSync(parent);if(!stat.isDirectory()||stat.isSymbolicLink())fail();}
 return fs.openSync(resolved,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
}
function captured(file,limit,hashOnly=false){
 const fd=open(file);try{
  const before=fs.fstatSync(fd);if(!before.isFile()||before.size<1||before.size>limit)fail();
  const hash=createHash('sha256'),parts=[],buffer=Buffer.alloc(1024*1024);let count=0;
  for(;;){const length=fs.readSync(fd,buffer,0,buffer.length,null);if(!length)break;count+=length;if(count>limit)fail();hash.update(buffer.subarray(0,length));if(!hashOnly)parts.push(Buffer.from(buffer.subarray(0,length)));}
  const after=fs.fstatSync(fd);if(count!==before.size||before.size!==after.size||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs)fail();
  return hashOnly?hash.digest('hex'):Buffer.concat(parts);
 }finally{fs.closeSync(fd);}
}
export function validateDatabaseMetadata(database,now=Date.now()){
 const updated=Date.parse(database?.UpdatedAt),next=Date.parse(database?.NextUpdate),downloaded=Date.parse(database?.DownloadedAt);
 if(!Number.isSafeInteger(now)||![updated,next,downloaded].every(Number.isFinite)||database.Version!==2||updated>now+60000||now-updated>86400000||next<=now||next<=updated||downloaded<updated||downloaded>now+60000||! /^[a-f0-9]{64}$/.test(database.sha256||''))fail();
 return database;
}
export function nativeDatabase(root,runIdentity,{now=Date.now()}={}){
 const cache=path.join(root,'database');
 const execution=parseJson(captured(path.join(root,'fresh/trivy/execution.json'),100000),'execution');
 if(execution.status!==0||execution.network!=='none'||execution.sourceMounted!==false||execution.credentialsPassed!==false||execution.repository!==runIdentity.repository||execution.runId!==runIdentity.run||String(execution.runAttempt)!==runIdentity.attempt||execution.sourceRevision!==runIdentity.source||execution.toolsRevision!==runIdentity.tools)fail();
 const metadata=captured(path.join(cache,'db/metadata.json'),100000),database=parseJson(metadata,'execution');
 database.sha256=captured(path.join(cache,'db/trivy.db'),2_000_000_000,true);
 for(const key of ['Version','UpdatedAt','NextUpdate','DownloadedAt','sha256'])if(database[key]!==execution.database?.[key])fail();
 validateDatabaseMetadata(database,now);
 return {cache,database,metadataSha256:createHash('sha256').update(metadata).digest('hex')};
}
export function sameDatabase(before,after){if(JSON.stringify(before)!==JSON.stringify(after))fail();return true;}
export function validateRuntimeExecution(scan,report,{now=Date.now()}={}){
 const start=Date.parse(scan?.startedAt),end=Date.parse(scan?.finishedAt),created=Date.parse(report?.CreatedAt);
 if(scan?.network!=='none'||scan.cacheReadOnly!==true||!Number.isSafeInteger(now)||![start,end,created].every(Number.isFinite)||end<start||end-start>600000||end>now+1000||now-end>3600000||created<start-60000||created>end+60000||! /^[a-f0-9]{64}$/.test(scan.metadataSha256||''))fail();
 validateDatabaseMetadata(scan.database,now);return true;
}
