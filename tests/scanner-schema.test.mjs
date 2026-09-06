import test from 'node:test';
import assert from 'node:assert/strict';
import {validateOsvReport,validateSemgrepReport,validateTrivyConfigReport} from '../tools/static-pages/scanner-schema.mjs';
const clone=value=>structuredClone(value);
const osv={results:[{source:{path:'/source/requirements.txt',type:'lockfile'},packages:[{package:{name:'example',version:'1.0.0',ecosystem:'PyPI'},vulnerabilities:[{id:'CVE-2026-12345',details:'PRIVATE_SOURCE_MUST_NOT_BE_EMITTED'}]}]}]};
const semgrep={version:'1.176.0',results:[{check_id:'synthetic.security.eval',path:'/source/app.py',start:{line:2,col:1,offset:4},end:{line:2,col:8,offset:11},extra:{lines:'PRIVATE_SOURCE_MUST_NOT_BE_EMITTED',message:'untrusted instructions'}}],errors:[],paths:{scanned:['/source/app.py']}};
const config={SchemaVersion:2,ArtifactName:'/source',ArtifactType:'filesystem',Results:[{Target:'Dockerfile',Class:'config',Type:'dockerfile',MisconfSummary:{Successes:20,Failures:0}}]};
function blocks(fn,value){assert.throws(()=>fn(value),/^Error: Invalid (?:OSV|Semgrep|Trivy configuration) scanner report$/);}
test('OSV clean output has an explicit empty results array',()=>assert.deepEqual(validateOsvReport({results:[],experimental_config:{}}),[]));
test('OSV returns only advisory IDs and drops raw package/source metadata',()=>assert.deepEqual(validateOsvReport(osv),[{id:'CVE-2026-12345'}]));
test('OSV rejects malformed roots and missing results, without the exit128 exception',()=>{for(const x of [null,[],{},'x',{results:null},{results:{}}])blocks(validateOsvReport,x);});
test('OSV rejects malformed nested result source and package arrays',()=>{for(const change of [x=>x.results=[null],x=>delete x.results[0].source,x=>x.results[0].source.path='',x=>x.results[0].source.type=7,x=>delete x.results[0].packages,x=>x.results[0].packages={}]){const x=clone(osv);change(x);blocks(validateOsvReport,x);}});
test('OSV rejects incomplete package identities and malformed vulnerabilities',()=>{for(const change of [x=>x.results[0].packages=[null],x=>x.results[0].packages[0].package={},x=>x.results[0].packages[0].package.version=1,x=>delete x.results[0].packages[0].vulnerabilities,x=>x.results[0].packages[0].vulnerabilities={},x=>x.results[0].packages[0].vulnerabilities=[{}],x=>x.results[0].packages[0].vulnerabilities=[null],x=>x.results[0].packages[0].vulnerabilities[0].id='x\nPRIVATE_SOURCE_MUST_NOT_BE_EMITTED']){const x=clone(osv);change(x);blocks(validateOsvReport,x);}});
test('Semgrep no-language-target output is valid only with explicit required fields',()=>assert.deepEqual(validateSemgrepReport({version:'1.176.0',results:[],errors:[],paths:{scanned:[]}}),[]));
test('Semgrep returns only bounded finding locations',()=>assert.deepEqual(validateSemgrepReport(semgrep),[{rule:'synthetic.security.eval',path:'/source/app.py',line:2}]));
test('Semgrep rejects missing arrays/version/paths and malformed scanned locations',()=>{for(const change of [x=>delete x.version,x=>x.version=1,x=>delete x.results,x=>x.results={},x=>delete x.errors,x=>x.errors=null,x=>delete x.paths,x=>delete x.paths.scanned,x=>x.paths.scanned=[null],x=>x.paths.scanned=['x\nprivate']]){const x=clone(semgrep);change(x);blocks(validateSemgrepReport,x);}});
test('Semgrep analysis errors block without exposing raw diagnostics',()=>{const x=clone(semgrep);x.errors=[{message:'PRIVATE_SOURCE_MUST_NOT_BE_EMITTED'}];blocks(validateSemgrepReport,x);});
test('Semgrep rejects malformed nested finding identities and positions',()=>{for(const change of [x=>x.results=[null],x=>delete x.results[0].check_id,x=>x.results[0].path='',x=>delete x.results[0].start,x=>x.results[0].start.line=0,x=>x.results[0].start.offset=-1,x=>x.results[0].start.line=Infinity,x=>x.results[0].end.line=1,x=>x.results[0].extra=[]]){const x=clone(semgrep);change(x);blocks(validateSemgrepReport,x);}});
test('Trivy real no-target filesystem output can omit Results or use an empty array',()=>{for(const x of [{SchemaVersion:2,ArtifactName:'/source',ArtifactType:'filesystem'},{SchemaVersion:2,ArtifactName:'/source',ArtifactType:'filesystem',Results:[]}])assert.deepEqual(validateTrivyConfigReport(x),[]);});
test('Trivy successful config target can omit Misconfigurations',()=>assert.deepEqual(validateTrivyConfigReport(config),[]));
test('Trivy config reports may include language package targets',()=>{const x=clone(config);x.Results.unshift({Target:'requirements.txt',Class:'lang-pkgs',Type:'pip',Packages:[{Name:'example',Version:'1.0.0'}]});assert.deepEqual(validateTrivyConfigReport(x),[]);});
test('Trivy preserves existing HIGH/CRITICAL policy and drops raw code',()=>{const x=clone(config);x.Results[0].MisconfSummary.Failures=5;x.Results[0].Misconfigurations=['LOW','MEDIUM','UNKNOWN','HIGH','CRITICAL'].map((Severity,i)=>({ID:'SYNTHETIC-'+i,Severity,Status:'FAIL',CauseMetadata:{Code:{Lines:[{Content:'PRIVATE_SOURCE_MUST_NOT_BE_EMITTED'}]}}}));assert.deepEqual(validateTrivyConfigReport(x),[{id:'SYNTHETIC-3',path:'Dockerfile',severity:'HIGH'},{id:'SYNTHETIC-4',path:'Dockerfile',severity:'CRITICAL'}]);});
test('Trivy rejects malformed config report roots, targets and summaries',()=>{for(const change of [x=>delete x.SchemaVersion,x=>x.ArtifactType='container_image',x=>delete x.ArtifactName,x=>x.Results=null,x=>x.Results=[{}],x=>x.Results[0].Class='unsupported',x=>delete x.Results[0].MisconfSummary,x=>x.Results[0].MisconfSummary.Failures=-1,x=>x.Results[0].MisconfSummary.Successes=Infinity,x=>x.Results[0].MisconfSummary.Failures=1]){const x=clone(config);change(x);blocks(validateTrivyConfigReport,x);}});
test('Trivy rejects malformed or hidden dependency/config findings',()=>{for(const entry of [null,{}, {ID:'X',Severity:'TYPO'},{ID:'X',Severity:'HIGH',Status:'invalid'},{ID:'private\nvalue',Severity:'HIGH'}]){const x=clone(config);x.Results[0].Misconfigurations=[entry];blocks(validateTrivyConfigReport,x);}const x=clone(config);x.Results[0].Vulnerabilities=[{VulnerabilityID:'CVE-2026-12345',Severity:'HIGH'}];blocks(validateTrivyConfigReport,x);});
test('Trivy malformed package-only targets cannot stand in for successful config coverage',()=>{for(const target of [{Target:'requirements.txt',Class:'lang-pkgs',Type:'pip'},{Target:'requirements.txt',Class:'lang-pkgs',Type:'pip',Packages:[{}]}]){const x=clone(config);x.Results=[target];blocks(validateTrivyConfigReport,x);}});
test('project-controlled diagnostic text is never copied into successful projections or thrown errors',()=>{for(const [fn,x] of [[validateOsvReport,osv],[validateSemgrepReport,semgrep],[validateTrivyConfigReport,config]])assert.doesNotMatch(JSON.stringify(fn(x)),/PRIVATE_SOURCE_MUST_NOT_BE_EMITTED/);});

test('Trivy fs on a committed Git checkout reports repository and keeps the same config policy',()=>{
 const repository={...clone(config),ArtifactType:'repository'};
 assert.deepEqual(validateTrivyConfigReport(repository),[]);
 repository.Results[0].MisconfSummary.Failures=1;
 repository.Results[0].Misconfigurations=[{ID:'SYNTHETIC-HIGH',Severity:'HIGH',Status:'FAIL'}];
 assert.deepEqual(validateTrivyConfigReport(repository),[{id:'SYNTHETIC-HIGH',path:'Dockerfile',severity:'HIGH'}]);
 for(const Results of [undefined,[]]){
  const empty={SchemaVersion:2,ArtifactName:'/synthetic-checkout',ArtifactType:'repository'};
  if(Results!==undefined)empty.Results=Results;
  assert.deepEqual(validateTrivyConfigReport(empty),[]);
 }
});
test('config artifact admission rejects unrelated types and keeps repository structure validation strict',()=>{
 for(const ArtifactType of ['container_image','rootfs','vm','',null,{},[]])blocks(validateTrivyConfigReport,{...clone(config),ArtifactType});
 for(const change of [x=>x.SchemaVersion=1,x=>delete x.ArtifactName,x=>x.Results=[{}],x=>x.Results[0].MisconfSummary.Failures=1]){
  const x={...clone(config),ArtifactType:'repository'};change(x);blocks(validateTrivyConfigReport,x);
 }
});
