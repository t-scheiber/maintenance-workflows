// Dependency-free public control tests execute only inside the freshly admitted Node24 image.
import fs from 'node:fs';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {preparedScanner} from './prepared-scanners.mjs';
import {inspectSource} from './pages-build.mjs';
export const controlCommand='node --test tests/*.test.mjs && python3 -m unittest discover -s tests -p "test_*.py" && node scripts/check-config.mjs';
export function controlArguments(source,image){
 if(!path.isAbsolute(source)||!/^sha256:[a-f0-9]{64}$/.test(image))throw Error('Exact control source/runtime required');
 return ['run','--name','public-control-tests-'+randomUUID(),'--platform','linux/amd64','--network','none','--read-only','--user',`${process.getuid()}:${process.getgid()}`,'--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','256','--memory','3g','--cpus','2','--tmpfs','/tmp:rw,exec,nosuid,nodev,size=1g','--mount',`type=bind,src=${source},dst=/work,readonly`,'--workdir','/work','--env','HOME=/tmp','--env','PYTHONDONTWRITEBYTECODE=1','--env','CI=true','--entrypoint','/bin/sh',image,'-ec',`test "$(node --version)" = v24.20.0; test "$(command -v python3)" = /usr/bin/python3; test "$(dpkg-query -S /usr/bin/python3)" = 'python3-minimal: /usr/bin/python3'; ${controlCommand}`];
}
export function runControlTests({source=process.cwd(),admit=preparedScanner,execute=spawnSync,env=process.env}={}){
 const admitted=admit('trivy',{env});
 source=path.resolve(source);inspectSource(source);
 const args=controlArguments(source,admitted.runtimeImage),name=args[args.indexOf('--name')+1];
 let result,cleanup;
 try{result=execute(admitted.dockerCommand,args,{env:admitted.dockerEnvironment,encoding:'utf8',timeout:600000,maxBuffer:8_000_000});}
 finally{cleanup=execute(admitted.dockerCommand,['rm','-f',name],{env:admitted.dockerEnvironment,encoding:'utf8',timeout:30000,maxBuffer:100000});}
 // These are public repository test logs from a credential-free, network-disabled process.
 const receipt={schema:1,status:!result.error&&result.status===0&&!cleanup.error&&cleanup.status===0?'PASS':'BLOCK',runIdentity:admitted.runIdentity,executionImage:admitted.runtimeImage,runtimeConfig:admitted.runtime.configId,network:'none',credentialsPassed:false,commands:controlCommand.split(' && '),exitCode:result.status,cleanup:!cleanup.error&&cleanup.status===0?'PASS':'BLOCK'};
 const output=path.join(env.RUNNER_TEMP,'control-tests');fs.mkdirSync(output,{mode:0o700});
 fs.writeFileSync(path.join(output,'receipt.json'),JSON.stringify(receipt,null,2)+'\n',{flag:'wx',mode:0o600});
 fs.writeFileSync(path.join(output,'stdout.log'),result.stdout??'',{flag:'wx',mode:0o600});fs.writeFileSync(path.join(output,'stderr.log'),result.stderr??'',{flag:'wx',mode:0o600});
 if(receipt.status!=='PASS')throw Error('Isolated public control tests failed');return receipt;
}
if(process.argv[1]&&path.resolve(process.argv[1])===import.meta.filename){if(process.argv.length!==2)throw Error('Unexpected control test arguments');console.log(JSON.stringify(runControlTests()));}
