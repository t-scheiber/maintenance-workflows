import test from 'node:test';
import assert from 'node:assert/strict';
import {controlArguments,controlCommand,runControlTests} from '../tools/static-pages/control-tests.mjs';
test('control tests require immutable runtime and run every suite offline without host authority',()=>{
 const args=controlArguments('/synthetic/source','sha256:'+'a'.repeat(64));
 assert.equal(args[args.indexOf('--network')+1],'none');assert.equal(args[args.indexOf('--entrypoint')+1],'/bin/sh');
 assert.ok(args.includes('--read-only'));assert.ok(args.includes('type=bind,src=/synthetic/source,dst=/work,readonly'));
 assert.ok(args.at(-1).includes(controlCommand));assert.match(args.at(-1),/dpkg-query -S/);assert.match(controlCommand,/node --test/);assert.match(controlCommand,/unittest discover/);assert.match(controlCommand,/check-config/);
 assert.ok(!args.some(x=>/docker.sock|TOKEN|API_KEY/.test(x)));
 for(const image of ['node:24','sha256:bad',''])assert.throws(()=>controlArguments('/source',image));assert.throws(()=>controlArguments('../source','sha256:'+'a'.repeat(64)));
});
test('missing native evidence stops control tests before source inspection or container execution',()=>{
 let executed=false;assert.throws(()=>runControlTests({source:'/does-not-exist',admit(){throw Error('PROTECTED_RECORD_PENDING');},execute(){executed=true;}}),/PROTECTED_RECORD_PENDING/);assert.equal(executed,false);
});

test('failed or timed out control suite always removes its exact isolated container and blocks aggregate',async t=>{
 const fs=await import('node:fs'),os=await import('node:os'),path=await import('node:path');
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'control-timeout-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const source=path.join(root,'source');fs.mkdirSync(source);fs.writeFileSync(path.join(source,'README.md'),'synthetic test source');
 const calls=[];const admitted={dockerCommand:'/synthetic/docker',dockerEnvironment:{PATH:'/synthetic'},runtimeImage:'sha256:'+'a'.repeat(64),runtime:{configId:'sha256:'+'b'.repeat(64)},runIdentity:{run:'123'}};
 assert.throws(()=>runControlTests({source,env:{RUNNER_TEMP:root},admit:()=>admitted,execute(command,args,options){calls.push({command,args,options});return args[0]==='run'?{status:null,error:Error('synthetic timeout'),stdout:'',stderr:''}:{status:0};}}),/control tests failed/);
 assert.equal(calls.length,2);const name=calls[0].args[calls[0].args.indexOf('--name')+1];assert.deepEqual(calls[1].args,['rm','-f',name]);assert.equal(calls[1].options.timeout,30000);
 const receipt=JSON.parse(fs.readFileSync(path.join(root,'control-tests/receipt.json')));assert.equal(receipt.status,'BLOCK');assert.equal(receipt.cleanup,'PASS');
});
