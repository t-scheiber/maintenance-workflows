import test from 'node:test';
import assert from 'node:assert/strict';
import {validateRuntimeScan} from '../tools/static-pages/runtime-scan.mjs';
const imageId='sha256:'+'a'.repeat(64);
const options={status:0,imageId,platform:'linux/amd64',stderr:'2026 INFO Vulnerability scanning is enabled'};
function pkg(name,version='1.0.0',path){return{ID:name+'@'+version,Name:name,Version:version,Identifier:{PURL:'pkg:npm/'+name+'@'+version},...(path?{FilePath:path}:{})};}
function report(){return{SchemaVersion:2,ArtifactType:'container_image',Trivy:{Version:'0.74.0'},Metadata:{ImageID:imageId,OS:{Family:'ubuntu',Name:'24.04'},ImageConfig:{architecture:'amd64',os:'linux'}},Results:[{Target:'archive.tar.gz (ubuntu 24.04)',Class:'os-pkgs',Type:'ubuntu',Packages:[pkg('libc6')]},{Target:'Node.js',Class:'lang-pkgs',Type:'node-pkg',Packages:[pkg('npm','12.0.2','usr/local/maintenance-npm/package.json')]}]};}
const finding=Severity=>({VulnerabilityID:'CVE-2026-1234',PkgID:'libc6@1.0.0',PkgName:'libc6',InstalledVersion:'1.0.0',Severity});
test('real-shaped image coverage includes per-target inventories and visible allowed severities',()=>{
 const value=report();value.Results[0].Vulnerabilities=[finding('LOW'),finding('MEDIUM')];const result=validateRuntimeScan(value,options);
 assert.equal(result.packages,2);assert.equal(result.severities.LOW,1);assert.equal(result.severities.MEDIUM,1);assert.equal(result.targets.find(t=>t.class==='os-pkgs').target,'operating-system');assert.match(result.targets[0].inventorySha256,/^[a-f0-9]{64}$/);
});
test('empty, malformed, partial or identity-mismatched runtime reports cannot pass',()=>{
 for(const mutate of [()=>null,()=>({}),x=>({...x,Results:[{}]}),x=>({...x,Results:[]}),x=>({...x,SchemaVersion:1}),x=>({...x,ArtifactType:'filesystem'}),x=>({...x,Trivy:{Version:'0.73.0'}}),x=>({...x,Metadata:{...x.Metadata,ImageID:'sha256:'+'b'.repeat(64)}}),x=>({...x,Metadata:{...x.Metadata,ImageConfig:{architecture:'arm64',os:'linux'}}}),x=>({...x,Results:x.Results.slice(1)})])assert.throws(()=>validateRuntimeScan(mutate(report()),options));
 for(const status of [1,128,137,null,undefined])assert.throws(()=>validateRuntimeScan(report(),{...options,status}));
});
test('missing inventory, bad package identity and conflicting types fail closed',()=>{
 for(const mutate of [r=>delete r.Packages,r=>r.Packages=[],r=>r.Packages[0].Version={},r=>r.Packages[0].Identifier.PURL='',r=>r.Packages[0].Release={},r=>r.Packages.push({...r.Packages[0]}),r=>r.Type='alpine',r=>r.Packages[0].Epoch=-1]){const value=report();mutate(value.Results[0]);assert.throws(()=>validateRuntimeScan(value,options));}
});
test('every vulnerability must bind a reported package and a recognized allowed severity',()=>{
 for(const vulnerability of [finding('HIGH'),finding('CRITICAL'),finding('UNKNOWN'),finding('low'),finding('UNRECOGNIZED'),{}, {...finding('LOW'),PkgID:'absent@1.0.0'},{...finding('LOW'),PkgName:'other'}]){const value=report();value.Results[0].Vulnerabilities=[vulnerability];assert.throws(()=>validateRuntimeScan(value,options));}
 for(const Vulnerabilities of [{},null,'none']){const value=report();value.Results[0].Vulnerabilities=Vulnerabilities;assert.throws(()=>validateRuntimeScan(value,options));}
});
test('warnings/errors and missing vulnerability details reject even without a log severity prefix',()=>{
 for(const stderr of [undefined,'WARN analysis incomplete','ERROR analysis failed','failed to get vulnerability detail','missing vulnerability details','2026 INFO vulnerability details unavailable'])assert.throws(()=>validateRuntimeScan(report(),{...options,stderr}));
 for(const key of ['Warnings','Errors','warnings','errors']){const value=report();value[key]=['unavailable'];assert.throws(()=>validateRuntimeScan(value,options));const nested=report();nested.Results[0][key]=['unavailable'];assert.throws(()=>validateRuntimeScan(nested,options));}
});
test('expected package versions/paths and target classes cannot be substituted',()=>{
 const requiredPackages=[{class:'lang-pkgs',type:'node-pkg',name:'npm',version:'12.0.2',filePath:'usr/local/maintenance-npm/package.json'}];assert.equal(validateRuntimeScan(report(),{...options,requiredPackages}).requiredPackages.length,1);
 for(const mutation of [{version:'12.0.1'},{filePath:'other'},{name:'renovate'}])assert.throws(()=>validateRuntimeScan(report(),{...options,requiredPackages:[{...requiredPackages[0],...mutation}]}));
 assert.throws(()=>validateRuntimeScan(report(),{...options,requiredTargets:[{class:'lang-pkgs',type:'gobinary'}]}));
});
test('fixed expected coverage binds every package identity but ignores transport-specific layer metadata',()=>{
 const value=report(),expectedCoverage=validateRuntimeScan(value,options).targets;
 const transported=structuredClone(value);transported.Results[0].Target='other/runtime.tar (ubuntu 24.04)';transported.Results[0].Packages[0].Layer={Digest:'changed-compressed-layer',DiffID:'unchanged-content'};transported.Results[0].Packages[0].Identifier.UID='transport-dependent';
 assert.deepEqual(validateRuntimeScan(transported,{...options,expectedCoverage}).targets,expectedCoverage);
 for(const mutation of [v=>v.Results[0].Packages.push(pkg('extra')),v=>v.Results[0].Packages[0].Release='0ubuntu2',v=>v.Results[0].Packages[0].Identifier.PURL='pkg:npm/other@1.0.0',v=>v.Results.pop()]){const changed=report();mutation(changed);assert.throws(()=>validateRuntimeScan(changed,{...options,expectedCoverage}));}
 const reordered=expectedCoverage.map(t=>({inventorySha256:t.inventorySha256,packages:t.packages,target:t.target,type:t.type,class:t.class}));assert.doesNotThrow(()=>validateRuntimeScan(report(),{...options,expectedCoverage:reordered}));
});
test('actual Python metadata rows may omit ID without losing inventory identity or finding binding',()=>{
 const value=report(),python={Name:'PyJWT',Version:'2.13.0',Identifier:{PURL:'pkg:pypi/pyjwt@2.13.0'},FilePath:'usr/lib/python3.12/site-packages/pyjwt-2.13.0.dist-info/METADATA'};
 value.Results[1]={Target:'Python',Class:'lang-pkgs',Type:'python-pkg',Packages:[python]};
 const coverage=validateRuntimeScan(value,options);assert.equal(coverage.packages,2);assert.ok(!Object.hasOwn(python,'ID'));
 const finding={VulnerabilityID:'CVE-2026-1234',PkgName:'PyJWT',InstalledVersion:'2.13.0',Severity:'LOW'};value.Results[1].Vulnerabilities=[finding];assert.equal(validateRuntimeScan(value,options).severities.LOW,1);
 for(const patch of [{ID:null},{ID:''},{Identifier:{PURL:'pkg:npm/pyjwt@2.13.0'}},{FilePath:undefined}]){const copy=structuredClone(value);copy.Results[1].Packages[0]={...python,...patch};assert.throws(()=>validateRuntimeScan(copy,options));}
 for(const patch of [{PkgName:'other'},{InstalledVersion:'2.12.0'},{PkgID:'invented'},{PkgPath:'other/path'},{Severity:'HIGH'},{Severity:'CRITICAL'},{Severity:'UNKNOWN'}]){const copy=structuredClone(value);copy.Results[1].Vulnerabilities=[{...finding,...patch}];assert.throws(()=>validateRuntimeScan(copy,options));}
 const ambiguous=structuredClone(value);ambiguous.Results[1].Packages.push({...python,FilePath:'other/pyjwt.dist-info/METADATA'});assert.throws(()=>validateRuntimeScan(ambiguous,options));ambiguous.Results[1].Vulnerabilities[0].PkgPath=python.FilePath;assert.equal(validateRuntimeScan(ambiguous,options).packages,3);
 const missingNode=report();delete missingNode.Results[1].Packages[0].ID;assert.throws(()=>validateRuntimeScan(missingNode,options));
 const changed=structuredClone(value);changed.Results[1].Packages[0].FilePath='other/METADATA';assert.throws(()=>validateRuntimeScan(changed,{...options,expectedCoverage:coverage.targets}));
});
