// SPDX-License-Identifier: MIT
// Only protected control policy can establish authority. Release evidence cannot.
import {canonical,fingerprint,reject,parseJson,validateNativeAdmission} from './native-admission.mjs';
import {loadNativeEvidence} from './native-evidence.mjs';
export const TOOLS=Object.freeze(['gitleaks','osv-scanner','trivy']);
const FILES=Object.freeze({report:'report.json',stderr:'stderr.log',graph:'graph.jsonl',manifest:'manifest.json',buildInfo:'build-info.txt',pclntab:'pclntab.json',advisory:'advisory.json',execution:'execution.json',provenance:'provenance.json',binary:'binary'});
const hex=(x,n=64)=>typeof x==='string'&&new RegExp(`^[a-f0-9]{${n}}$`).test(x);
const id=x=>typeof x==='string'&&/^[1-9][0-9]{0,19}$/.test(x);
const keys=(x,list)=>x&&typeof x==='object'&&!Array.isArray(x)&&Object.keys(x).sort().join(',')===list.toSorted().join(',');
const same=(a,b)=>canonical(a)===canonical(b);
export function validateSourceAuthority(authority,pending){
 if(authority?.state!=='protected-control-plane')reject('SOURCE_AUTHORITY_PENDING');
 if(!keys(authority,['version','state','repository','hostedProof','transport','records'])||authority.version!==1||authority.repository!=='t-scheiber/renovate-config')reject('SOURCE_AUTHORITY');
 if(!same(authority.transport,{manifestSha256:'2b8524bd071220bf1927e3772630b047ac11f4f0dfcea4d7fbcb404a282ecbaa',archiveSha256:'7ddcdefc8bbac157623353b56944171b0c16899afbf7c36c1b59af8c86c742ec',assetId:547257811}))reject('SOURCE_TRANSPORT');
 const proof=authority.hostedProof;
 if(!keys(proof,['sourceCommit','workflowPath','runId','runAttempt','conclusion','event','ref','actor','triggeringActor','artifactId','artifactDigest','artifactBytes','summarySha256','verificationReceiptSha256'])||!hex(proof.sourceCommit,40)||proof.workflowPath!=='.github/workflows/verify-native-bundle.yml'||!id(proof.runId)||proof.runAttempt!==1||proof.conclusion!=='success'||proof.event!=='workflow_dispatch'||proof.ref!=='refs/heads/main'||proof.actor!=='t-scheiber'||proof.triggeringActor!=='t-scheiber'||!id(proof.artifactId)||!hex(proof.artifactDigest)||!Number.isSafeInteger(proof.artifactBytes)||proof.artifactBytes<1||proof.artifactBytes>400000000||!hex(proof.summarySha256)||!hex(proof.verificationReceiptSha256))reject('SOURCE_HOSTED_PROOF');
 if(pending?.state!=='pending-only'||!keys(pending.records,TOOLS)||!keys(authority.records,TOOLS))reject('SOURCE_REGISTRY');
 for(const tool of TOOLS){
  const original=pending.records[tool],selected=authority.records[tool];
  if(!keys(selected,['record','recordSha256'])||original.record.state!=='pending'||original.record.tool!==tool||fingerprint(original.record)!==original.recordSha256)reject('SOURCE_PENDING_IDENTITY');
  const expected={...original.record,state:'protected',controlPlaneRepository:'t-scheiber/renovate-config',controlPlaneCommit:proof.sourceCommit};
  if(!same(selected.record,expected)||fingerprint(selected.record)!==selected.recordSha256)reject('SOURCE_RECORD_DELTA');
 }
 return {authoritySha256:fingerprint(authority),hostedSourceCommit:proof.sourceCommit,hostedRunId:proof.runId};
}
export function validateSourceRun(run){
 if(!keys(run,['repository','sourceRevision','toolsRevision','runId','runAttempt','now'])||!['t-scheiber/renovate-config','t-scheiber/maintenance-workflows','t-scheiber/AK_WeatherApp','t-scheiber/ScheiberVueAppAbgabe'].includes(run.repository)||!hex(run.sourceRevision,40)||!hex(run.toolsRevision,40)||!id(run.runId)||!Number.isSafeInteger(run.runAttempt)||run.runAttempt<1||run.runAttempt>1000||!Number.isSafeInteger(run.now)||run.now<1)reject('SOURCE_RUN');
}
export function validateSourceExecution(execution,run){
 validateSourceRun(run);
 if(execution?.repository!==run.repository||execution.network!=='none'||execution.sourceMounted!==false||execution.credentialsPassed!==false||execution.runId!==run.runId||execution.runAttempt!==run.runAttempt||execution.sourceRevision!==run.sourceRevision||execution.toolsRevision!==run.toolsRevision)reject('SOURCE_RUN_BINDING');
}
export function admitSourceTools(root,authority,pending,run){
 // These checks deliberately precede filesystem IO. Pending evidence is diagnostic only.
 const binding=validateSourceAuthority(authority,pending);validateSourceRun(run);
 if(typeof root!=='string'||!root.startsWith('/')||root.endsWith('/'))reject('SOURCE_EVIDENCE_ROOT');
 const receipts=[];
 for(const tool of TOOLS){
  const input=loadNativeEvidence(`${root}/${tool}`,FILES);
  validateSourceExecution(parseJson(input.execution,'execution'),run);
  const selected=authority.records[tool];
  const receipt=validateNativeAdmission(input,selected.record,{recordSha256:selected.recordSha256,now:run.now});
  if(receipt.status!=='PASS_WITH_REVIEWED_NOT_AFFECTED'||receipt.reason!=='EXACT_VULNERABLE_CODE_NOT_PRESENT'||receipt.tool!==tool)reject('SOURCE_TOOL_BLOCK');
  receipts.push(receipt);
 }
 return {version:1,status:'NATIVE_SOURCE_TOOLS_ADMITTED',...binding,runId:run.runId,runAttempt:run.runAttempt,sourceRevision:run.sourceRevision,toolsRevision:run.toolsRevision,tools:receipts};
}
