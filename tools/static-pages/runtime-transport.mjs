// SPDX-License-Identifier: MIT
// Transport-only gzip normalization. Every decoded byte is counted and hashed; no image code is run.
import fs from 'node:fs';
import path from 'node:path';
import {Transform} from 'node:stream';
import {pipeline} from 'node:stream/promises';
import {createHash} from 'node:crypto';
import {createGzip,createGunzip,constants} from 'node:zlib';
export const transportLimits=Object.freeze({artifactBytes:1_500_000_000,expandedBytes:2_000_000_000,timeoutMs:180000});
function limits(input={}) {
 const value={...transportLimits,...input};
 for(const name of Object.keys(value))if(!Object.hasOwn(transportLimits,name)||!Number.isSafeInteger(value[name])||value[name]<=0||value[name]>transportLimits[name])throw Error('Transport budget may only be reduced');
 return value;
}
class Meter extends Transform {
 constructor(max,tar=false){super();this.max=max;this.bytes=0;this.hash=createHash('sha256');this.tar=tar;this.minimum=tar?1024:1;this.prefix=Buffer.alloc(0);}
 _transform(chunk,encoding,done){try{
  this.bytes+=chunk.length;if(this.bytes>this.max)throw Error('Runtime transport byte budget exceeded');this.hash.update(chunk);
  if(this.tar){this.prefix=Buffer.concat([this.prefix,chunk]);if(this.prefix.length<512)return done();const header=this.prefix.subarray(0,512);if(header.subarray(257,262).toString()!=='ustar')throw Error('Expected plain tar after one gzip layer');const field=header.subarray(148,156).toString().replaceAll('\0','').trim();if(!/^[0-7]+$/.test(field))throw Error('Invalid tar checksum');let sum=0;for(let i=0;i<512;i++)sum+=(i>=148&&i<156)?32:header[i];if(sum!==parseInt(field,8))throw Error('Invalid tar checksum');this.tar=false;this.push(this.prefix);this.prefix=Buffer.alloc(0);}else this.push(chunk);done();
 }catch(error){done(error);}}
 _flush(done){done(this.tar||this.bytes<this.minimum?Error('Truncated runtime transport'):undefined);}
 digest(){return this.hash.digest('hex');}
}
async function write(output,stages,budget) {
 if(fs.existsSync(output))throw Error('Transport output already exists');
 let created=false;const stream=fs.createWriteStream(output,{flags:'wx',mode:0o600});stream.on('open',()=>{created=true;});
 try{await pipeline(...stages,stream,{signal:AbortSignal.timeout(budget.timeoutMs)});}catch(error){if(created)fs.rmSync(output,{force:true});throw error;}
}
export async function packRuntime(input,output,override={}) {
 const budget=limits(override),expanded=new Meter(budget.expandedBytes,true),artifact=new Meter(budget.artifactBytes);
 try{await write(output,[input,expanded,createGzip({level:constants.Z_BEST_SPEED}),artifact],budget);}catch(error){error.transport={status:'failed',compression:'gzip',archiveBytes:artifact.bytes,expandedArchiveBytes:expanded.bytes};throw error;}
 return {compression:'gzip',archiveBytes:artifact.bytes,archiveSha256:artifact.digest(),expandedArchiveBytes:expanded.bytes,expandedArchiveSha256:expanded.digest()};
}
export async function decodeRuntime(input,output,override={}) {
 const budget=limits(override),stat=fs.lstatSync(input);if(!stat.isFile()||stat.size>budget.artifactBytes)throw Error('Runtime archive exceeds bound');
 const fd=fs.openSync(input,'r');const magic=Buffer.alloc(2);try{fs.readSync(fd,magic,0,2,0);}finally{fs.closeSync(fd);}
 const compression=magic.equals(Buffer.from([0x1f,0x8b]))?'gzip':'none',artifact=new Meter(budget.artifactBytes),expanded=new Meter(budget.expandedBytes,true);
 const stages=[fs.createReadStream(input),artifact];if(compression==='gzip')stages.push(createGunzip());stages.push(expanded);
 await write(output,stages,budget);
 return {compression,archiveBytes:artifact.bytes,archiveSha256:artifact.digest(),expandedArchiveBytes:expanded.bytes,expandedArchiveSha256:expanded.digest()};
}
if(process.argv[1]&&path.resolve(process.argv[1])===import.meta.filename){
 const [mode,...args]=process.argv.slice(2);
 try{
 const result=mode==='pack'&&args.length===1?await packRuntime(process.stdin,args[0]):mode==='decode'&&args.length===2?await decodeRuntime(args[0],args[1]):null;
 if(!result)throw Error('Expected pack output or decode input output');console.log(JSON.stringify(result));
 }catch(error){console.log(JSON.stringify(error.transport||{status:'failed'}));console.error('Runtime transport rejected');process.exitCode=1;}
}
