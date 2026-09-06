import test from 'node:test';
import assert from 'node:assert/strict';
import {admitSourceScanners,sourcePolicy,pendingPolicy} from '../tools/native/source-admission.mjs';
import {validateSourceAuthority} from '../tools/native/native-source-authority.mjs';
test('actual public authority binds the successful hosted proof and still requires fresh source evidence',()=>{
 assert.equal(sourcePolicy().state,'protected-control-plane');assert.equal(validateSourceAuthority(sourcePolicy(),pendingPolicy()).hostedRunId,'34043216267');assert.equal(pendingPolicy().state,'pending-only');
 assert.throws(()=>admitSourceScanners('/does-not-exist'),/Public source identity differs/);
 for(const authority of [true,{state:'VERIFIED_PENDING_ONLY'},{status:'PASS'},{state:'protected-control-plane',adoption:true}])assert.throws(()=>validateSourceAuthority(authority,pendingPolicy()));
});
