// SPDX-License-Identifier: MIT
// Protected control code only. No repository source or credentials are accepted.
import fs from 'node:fs';
import {createHash} from 'node:crypto';
import {archiveIdentity} from '../static-pages/runtime-archive.mjs';
import {saveRuntimeImage as saveNodeImage} from '../static-pages/prepare-runtime.mjs';
import {validateRuntimeScan} from '../static-pages/runtime-scan.mjs';
const sha=data=>createHash('sha256').update(data).digest('hex');
function read(file,max){const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);try{const st=fs.fstatSync(fd);if(!st.isFile()||st.size>max)throw Error('Invalid bounded evidence');const data=fs.readFileSync(fd);if(data.length!==st.size)throw Error('Changed evidence');return data;}finally{fs.closeSync(fd);}}
export function expectedPending(code,stdout,stderr,tool){
 if(code!==1||stderr!==''||stdout.length>1000000)throw Error('Pending CLI failed');
 const value=JSON.parse(stdout);
 if(value.status!=='BLOCK'||value.reason!=='PROTECTED_RECORD_PENDING'||value.tool!==tool||value.rawInputsUnchanged!==true||!Array.isArray(value.decisions)||value.decisions.length!==1||value.decisions[0].status!=='pending')throw Error('Unexpected native admission');
 return value;
}
async function main(args){
 const [command,...rest]=args;
 const policy=JSON.parse(read(new URL('./policy/native-verification-runtime.json',import.meta.url),100000));
 if(command==='save'&&rest.length===2){
  await saveNodeImage(rest[0],rest[1],process.env);
  const identity=archiveIdentity(rest[1]);
  if(identity.imageId!==policy.imageId||identity.platform!==policy.platform)throw Error('Wrong transport image');
  return identity;
 }
 if(command==='runtime'&&rest.length===4){
  const [report,stderr,status,scanner]=rest;
  const scannerSha256=sha(read(scanner,400000000));
  return validateRuntimeScan(JSON.parse(read(report,32000000)),{...policy,status:Number(status),imageId:policy.imageId,stderr:read(stderr,2000000).toString('utf8'),scannerIdentity:{version:'0.74.0+maintenance.1',sha256:scannerSha256}});
 }
 if(command==='pending'&&rest.length===4)return expectedPending(Number(rest[0]),read(rest[1],1000000).toString('utf8'),read(rest[2],1000000).toString('utf8'),rest[3]);
 throw Error('Invalid verification command');
}
if(process.argv[1]===new URL(import.meta.url).pathname){try{process.stdout.write(JSON.stringify(await main(process.argv.slice(2)))+'\n');}catch{process.stderr.write('Native hosted evidence rejected\n');process.exitCode=1;}}
