// Docker daemon .Id can denote an OCI index. Bind Trivy to the actual hashed config in the saved archive.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
export function archiveIdentity(archive) {
 const stat=fs.statSync(archive);if(!stat.isFile()||stat.size>1_500_000_000)throw Error('Runtime archive exceeds bound');
 const temporary=fs.mkdtempSync(path.join(os.tmpdir(),'runtime-archive-'));
 try{
 const decoded=path.join(temporary,'decoded.tar');
 const transport=JSON.parse(execFileSync(process.execPath,[fileURLToPath(new URL('./runtime-transport.mjs',import.meta.url)),'decode',archive,decoded],{timeout:190000,maxBuffer:100000,env:{PATH:process.env.PATH}}));
 const read=name=>execFileSync('tar',['-xOf',decoded,name],{timeout:120000,maxBuffer:2_000_000});
 const manifest=JSON.parse(read('manifest.json'));
 if(!Array.isArray(manifest)||manifest.length!==1||!Array.isArray(manifest[0].Layers)||!manifest[0].Layers.length||manifest[0].Layers.length>100)throw Error('Runtime archive identity ambiguous');
 const filename=manifest[0].Config;
 if(typeof filename!=='string'||!(/^(?:blobs\/sha256\/[a-f0-9]{64}|[a-f0-9]{64}\.json)$/).test(filename))throw Error('Invalid runtime config path');
 const bytes=read(filename),digest=createHash('sha256').update(bytes).digest('hex');
 if(!filename.includes(digest))throw Error('Runtime config hash differs');
 const config=JSON.parse(bytes);
 if(config.os!=='linux'||!['amd64','arm64'].includes(config.architecture)||!Array.isArray(config.rootfs?.diff_ids)||config.rootfs.diff_ids.length!==manifest[0].Layers.length)throw Error('Invalid runtime platform or layers');
 return {publicationLabels:{source:config.config?.Labels?.['org.opencontainers.image.source']??null,description:config.config?.Labels?.['org.opencontainers.image.description']??null},imageId:'sha256:'+digest,platform:`${config.os}/${config.architecture}`,...transport};
 }finally{fs.rmSync(temporary,{recursive:true,force:true});}
}
