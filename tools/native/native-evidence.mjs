import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {LIMITS,reject,validateNativeAdmission} from './native-admission.mjs';
const fields=['report','stderr','graph','manifest','buildInfo','pclntab','advisory','execution','provenance','binary'];
// This adapter reads only fixed caller-selected evidence beneath one trusted mount.
// It runs no scanner, source code or network request and writes no report files.
export function loadNativeEvidence(root,relativeFiles){
 if(typeof root!=='string'||!path.isAbsolute(root)||!relativeFiles||Object.keys(relativeFiles).sort().join(',')!==fields.toSorted().join(','))reject('FILE_MAP');
 if(process.platform!=='linux')reject('EVIDENCE_PLATFORM');
 const rootStat=fs.lstatSync(root);if(!rootStat.isDirectory()||rootStat.isSymbolicLink())reject('EVIDENCE_ROOT');const base=fs.realpathSync(root);
 const input={};for(const key of fields){const relative=relativeFiles[key];if(typeof relative!=='string'||relative.length>4096||path.isAbsolute(relative)||relative.includes('\\')||relative.split('/').some(x=>!x||x==='.'||x==='..'))reject('EVIDENCE_PATH');let current=base;for(const segment of relative.split('/')){current=path.join(current,segment);let st;try{st=fs.lstatSync(current);}catch{reject('EVIDENCE_MISSING');}if(st.isSymbolicLink())reject('EVIDENCE_SYMLINK');if(current!==path.join(base,relative)&&!st.isDirectory())reject('EVIDENCE_PATH');if(current===path.join(base,relative)&&!st.isFile())reject('EVIDENCE_TYPE');}
 let fd;try{fd=fs.openSync(current,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);const opened=fs.realpathSync(`/proc/self/fd/${fd}`);if(!opened.startsWith(base+path.sep))reject('EVIDENCE_ESCAPE');const before=fs.fstatSync(fd);if(!before.isFile()||before.size<1||before.size>LIMITS[key])reject('FILE_BOUNDS');if(key==='binary'&&(before.mode&0o777)!==0o755)reject('BINARY_MODE');const hash=createHash('sha256'),chunks=[];let total=0;const buffer=Buffer.alloc(1024*1024);while(true){const count=fs.readSync(fd,buffer,0,buffer.length,null);if(!count)break;total+=count;if(total>LIMITS[key])reject('FILE_BOUNDS');hash.update(buffer.subarray(0,count));if(key!=='binary')chunks.push(Buffer.from(buffer.subarray(0,count)));}const after=fs.fstatSync(fd);if(total!==before.size||after.size!==before.size||after.ino!==before.ino||after.dev!==before.dev||after.mode!==before.mode||after.mtimeMs!==before.mtimeMs||after.ctimeMs!==before.ctimeMs)reject('EVIDENCE_CHANGED');input[key]=key==='binary'?{sha256:hash.digest('hex'),bytes:total,mode:before.mode&0o777}:Buffer.concat(chunks,total);
 }catch(e){if(e.code?.startsWith?.('E')&&!e.message.startsWith('Native scanner'))reject('EVIDENCE_IO');throw e;}finally{if(fd!==undefined)fs.closeSync(fd);}}
 return input;
}
export function admitNativeEvidence(root,files,record,options){return validateNativeAdmission(loadNativeEvidence(root,files),record,options);}
