import test from 'node:test';
import assert from 'node:assert/strict';
import {fixture,changeJson} from './native-fixture.mjs';
import {validateNativeAdmission,sha256,fingerprint,parseJson,LIMITS,VENDOR_WARNING} from '../tools/native/native-admission.mjs';
const run=f=>validateNativeAdmission(f.input,f.record,f.options);
const json=(f,n,edit)=>changeJson(f,n,edit);
function seal(f){for(const n of ['graph','manifest','buildInfo','pclntab','advisory'])f.record.evidence[n]=sha256(f.input[n]);const p=JSON.parse(f.input.provenance);Object.assign(p,{sourceManifestSha256:f.record.evidence.manifest,graphSha256:f.record.evidence.graph,buildInfoSha256:f.record.evidence.buildInfo,pclntabSha256:f.record.evidence.pclntab});f.input.provenance=Buffer.from(JSON.stringify(p));f.record.evidence.provenance=sha256(f.input.provenance);const e=JSON.parse(f.input.execution);e.reportSha256=sha256(f.input.report);e.stderrSha256=sha256(f.input.stderr);f.input.execution=Buffer.from(JSON.stringify(e));f.options.recordSha256=fingerprint(f.record);return f;}
function graph(f,edit){const rows=parseJson(f.input.graph,'graph',true);edit(rows);f.input.graph=Buffer.from(rows.map(JSON.stringify).join('\n'));}
test('exact synthetic protected record preserves raw UNKNOWN/WARN and all input bytes',()=>{const f=fixture(),before=Object.fromEntries(Object.entries(f.input).map(([k,v])=>[k,Buffer.isBuffer(v)?sha256(v):fingerprint(v)]));const r=run(f);assert.equal(r.status,'PASS_WITH_REVIEWED_NOT_AFFECTED');assert.equal(r.raw.findings,1);assert.equal(r.raw.severities.UNKNOWN,1);assert.equal(r.raw.warnings,1);assert.equal(r.decisions[0].status,'not_affected');for(const [k,v] of Object.entries(f.input))assert.equal(Buffer.isBuffer(v)?sha256(v):fingerprint(v),before[k]);});
test('pending control record and pending tests never authorize artifact',()=>{const f=fixture();f.record.state='pending';seal(f);assert.equal(run(f).reason,'PROTECTED_RECORD_PENDING');json(f,'provenance',p=>p.testsStatus='pending');seal(f);assert.equal(run(f).reason,'ARTIFACT_TESTS_PENDING');f.record.state='protected';seal(f);assert.equal(run(f).status,'BLOCK');assert.equal(run(f).decisions[0].status,'pending');});
const cases=[
 ['untrusted modified authority hash',f=>f.record.state='pending',false],
 ['wrong protected repository',f=>f.record.controlPlaneRepository='attacker/controls'],
 ['missing protected commit',f=>delete f.record.controlPlaneCommit],
 ['wrong fixed tool owner',f=>f.record.source.repository='google/osv-scanner'],
 ['wildcard compiler',f=>f.record.compiler='go1.*'],
 ['unbounded scan age',f=>f.record.scan.maxAgeMs=999999999],
 ['unknown compiler experiment',f=>{f.record.buildSettings.GOEXPERIMENT='other';f.input.buildInfo=Buffer.concat([f.input.buildInfo,Buffer.from('\tbuild\tGOEXPERIMENT=other\n')]);}],
 ['jsonv2 pairing mismatch',f=>f.record.buildSettings.GOEXPERIMENT='jsonv2'],
 ['different release tags',f=>f.record.buildSettings['-tags']='other'],
 ['binary substitution',f=>f.input.binary.sha256='9'.repeat(64)],
 ['binary size substitution',f=>f.input.binary.bytes++],
 ['nonexecutable mode',f=>f.input.binary.mode=420],
 ['manifest escape',f=>json(f,'manifest',x=>{x.files['../escape']=x.files['go.mod'];delete x.files['go.mod'];})],
 ['missing source file',f=>json(f,'manifest',x=>delete x.files['go.sum'])],
 ['source commit substitution',f=>json(f,'provenance',x=>x.sourceCommit='9'.repeat(40))],
 ['inspector identity substitution',f=>json(f,'provenance',x=>x.inspectorSha256='9'.repeat(64))],
 ['missing inspector test proof',f=>json(f,'provenance',x=>delete x.inspectorFixtureReceiptSha256)],
 ['source ran with network',f=>json(f,'provenance',x=>x.sourceExecutionNetwork='bridge')],
 ['binary inspection executed subject',f=>json(f,'provenance',x=>x.inspectedBinaryExecuted=true)],
 ['wrong compiler in buildinfo',f=>f.input.buildInfo=Buffer.from(f.input.buildInfo.toString().replace('go1.26.8','go1.26.7'))],
 ['CGO enabled',f=>f.input.buildInfo=Buffer.from(f.input.buildInfo.toString().replace('CGO_ENABLED=0','CGO_ENABLED=1'))],
 ['duplicate build module',f=>f.input.buildInfo=Buffer.concat([f.input.buildInfo,Buffer.from('\tdep\tgolang.org/x/crypto\tv0.56.0\th1:'+'a'.repeat(43)+'=\n')])],
 ['missing graph dependency',f=>graph(f,rows=>rows.pop())],
 ['dangling graph import',f=>graph(f,rows=>rows[0].Imports.push('absent/package'))],
 ['sibling graph main',f=>graph(f,rows=>rows[0].ImportPath='sibling/main')],
 ['duplicate graph row',f=>graph(f,rows=>rows[99]=structuredClone(rows[98]))],
 ['disconnected graph package',f=>graph(f,rows=>rows[0].Imports.pop())],
 ['real deprecated import',f=>graph(f,rows=>{rows[1].ImportPath='golang.org/x/crypto/openpgp';rows[0].Imports[0]=rows[1].ImportPath;})],
 ['graph module version mismatch',f=>graph(f,rows=>rows[1].Module.Version='v0.55.0')],
 ['graph module replacement',f=>graph(f,rows=>rows[1].Module.Replace={Path:'elsewhere'})],
 ['graph incomplete',f=>graph(f,rows=>rows[0].Incomplete=true)],
 ['graph compiler error',f=>graph(f,rows=>rows[0].Error={Err:'synthetic error'})],
 ['binary function metadata missing',f=>json(f,'pclntab',x=>delete x.functions)],
 ['positive deprecated pclntab',f=>json(f,'pclntab',x=>x.deprecatedOpenPgpFunctionCount=25)],
 ['pclntab sibling binary',f=>json(f,'pclntab',x=>x.binarySha256='9'.repeat(64))],
 ['pclntab function digest mismatch',f=>json(f,'pclntab',x=>x.functionNamesSha256='9'.repeat(64))],
 ['pclntab wrong main',f=>json(f,'pclntab',x=>x.mainPath='sibling/main')],
 ['advisory import removed',f=>json(f,'advisory',x=>x.affected[0].ecosystem_specific.imports.pop())],
 ['advisory changed range',f=>json(f,'advisory',x=>x.affected[0].ranges[0].events.push({fixed:'0.57.0'}))],
 ['advisory withdrawn',f=>json(f,'advisory',x=>x.withdrawn='2026-09-06T00:00:00Z')],
 ['advisory wrong module',f=>json(f,'advisory',x=>x.affected[0].package.name='different/module')],
 ['scan nonzero exit',f=>json(f,'execution',x=>x.status=1)],
 ['wrong runtime config',f=>json(f,'execution',x=>x.runtimeConfig='sha256:'+'9'.repeat(64))],
 ['wrong scanner binary',f=>json(f,'execution',x=>x.scannerSha256='9'.repeat(64))],
 ['wrong scan platform',f=>json(f,'execution',x=>x.platform='linux/arm64')],
 ['source mounted beside scanner',f=>json(f,'execution',x=>x.sourceMounted=true)],
 ['credentials beside scanner',f=>json(f,'execution',x=>x.credentialsPassed=true)],
 ['database absent',f=>json(f,'execution',x=>delete x.database)],
 ['database expired',f=>json(f,'execution',x=>x.database.NextUpdate='2026-09-06T13:00:00Z')],
 ['stale database',f=>json(f,'execution',x=>x.database.UpdatedAt='2026-09-01T00:00:00Z')],
 ['future database download',f=>json(f,'execution',x=>x.database.DownloadedAt='2026-09-07T00:00:00Z')],
 ['database malformed version',f=>json(f,'execution',x=>x.database.Version='2')],
 ['stale report',f=>f.options.now+=3600001],
 ['future report timestamp',f=>json(f,'report',x=>x.CreatedAt='2026-09-07T00:00:00Z')],
 ['wrong scanner report version',f=>json(f,'report',x=>x.Trivy.Version='0.74.0')],
 ['wrong artifact type',f=>json(f,'report',x=>x.ArtifactType='container_image')],
 ['zero analyzed targets',f=>json(f,'report',x=>x.Results=[])],
 ['extra target',f=>json(f,'report',x=>x.Results.push(structuredClone(x.Results[0])))],
 ['empty package coverage',f=>json(f,'report',x=>x.Results[0].Packages=[])],
 ['missing package',f=>json(f,'report',x=>x.Results[0].Packages.pop())],
 ['duplicate package',f=>json(f,'report',x=>x.Results[0].Packages[2]=structuredClone(x.Results[0].Packages[1]))],
 ['invented main version',f=>json(f,'report',x=>x.Results[0].Packages[0].Version='8.30.1')],
 ['wrong package PURL',f=>json(f,'report',x=>x.Results[0].Packages[1].Identifier.PURL='pkg:npm/other@1')],
 ['wrong package version',f=>json(f,'report',x=>x.Results[0].Packages[1].Version='v0.55.0')],
 ['changed package metadata',f=>json(f,'report',x=>x.Results[0].Packages[1].License='changed')],
 ['missing finding',f=>json(f,'report',x=>x.Results[0].Vulnerabilities=[])],
 ['duplicate finding',f=>json(f,'report',x=>x.Results[0].Vulnerabilities.push(structuredClone(x.Results[0].Vulnerabilities[0])))],
 ['extra critical finding',f=>json(f,'report',x=>x.Results[0].Vulnerabilities.push({VulnerabilityID:'NEW',Severity:'CRITICAL'}))],
 ['severity mutation',f=>json(f,'report',x=>x.Results[0].Vulnerabilities[0].Severity='LOW')],
 ['finding package mismatch',f=>json(f,'report',x=>x.Results[0].Vulnerabilities[0].PkgID='sibling@v0.56.0')],
 ['finding detail mutation',f=>json(f,'report',x=>x.Results[0].Vulnerabilities[0].Title='changed advisory')],
 ['report analysis error',f=>json(f,'report',x=>x.Errors=['synthetic error'])],
 ['report malformed warning shape',f=>json(f,'report',x=>x.Warnings={})],
 ['missing diagnostic capture',f=>f.input.stderr=Buffer.alloc(0)],
 ['vendor warning suffix',f=>f.input.stderr=Buffer.from(f.input.stderr.toString().trimEnd()+' extra\n')],
 ['extra vendor warning',f=>f.input.stderr=Buffer.concat([f.input.stderr,f.input.stderr])],
 ['real missing detail warning',f=>f.input.stderr=Buffer.from('2026-09-06T13:59:30Z\tWARN\tFailed to fetch vulnerability details\n')],
 ['missing details disguised INFO',f=>f.input.stderr=Buffer.from('2026-09-06T13:59:30Z\tINFO\tvulnerability details not found\n')],
 ['Docker platform warning',f=>f.input.stderr=Buffer.from('WARNING: platform mismatch\n')],
 ['embedded carriage return',f=>f.input.stderr=Buffer.from('2026-09-06T13:59:30Z\tWARN\t'+VENDOR_WARNING+'\rHIDDEN\n')],
];
for(const [name,edit,reseal=true] of cases)test(name,()=>{const f=fixture();edit(f);if(reseal)seal(f);assert.throws(()=>run(f),e=>e.message.startsWith('Native scanner admission rejected:')&&!e.message.includes('synthetic error'));});
test('report digest mismatch fails before report handling',()=>{const f=fixture();f.input.report=Buffer.concat([f.input.report,Buffer.from(' ')]);assert.throws(()=>run(f),{code:'EXECUTION_BINDING'});});
test('duplicate JSON keys, invalid UTF8, nesting and raw input budgets block',()=>{assert.throws(()=>parseJson(Buffer.from('{"Results":[],"Results":[]}')),{code:'JSON_DUPLICATE_KEY'});assert.throws(()=>parseJson(Buffer.from([0xff])),{code:'INPUT_ENCODING'});assert.throws(()=>parseJson(Buffer.from('['.repeat(45)+'0'+']'.repeat(45))),{code:'STRUCTURE_BUDGET'});assert.throws(()=>parseJson(Buffer.alloc(LIMITS.advisory+1,32),'advisory'),{code:'INPUT_BOUNDS'});assert.throws(()=>parseJson(Buffer.from('{"x":1e999}')),{code:'NONFINITE_NUMBER'});});
test('Go PURL normalization keeps exact module casing and encoded incompatible versions',()=>{const f=fixture();const r=JSON.parse(f.input.report),p=r.Results[0].Packages[1];p.Name='golang.org/x/Crypto';p.ID=p.Name+'@v0.56.0';r.Results[0].Packages[0].DependsOn[0]=p.ID;f.input.report=Buffer.from(JSON.stringify(r));seal(f);assert.throws(()=>run(f));assert.equal(p.Identifier.PURL,'pkg:golang/golang.org/x/crypto@v0.56.0');});
test('graph token budget supports complete larger streams but leaves ordinary JSON bounded',()=>{const graph=Buffer.from(Array.from({length:600},(_,i)=>JSON.stringify({ImportPath:'synthetic/'+i,Deps:Array(1000).fill('synthetic/value')})).join('\n'));assert.equal(parseJson(graph,'graph',true).length,600);assert.throws(()=>parseJson(Buffer.from(JSON.stringify({rows:Array(510000).fill(0)})),'report'),{code:'STRUCTURE_BUDGET'});});
test('corrected scanner requires its exact dev-docs warning and rejects old or arbitrary URLs',()=>{const f=fixture();assert.equal(run(f).raw.warnings,1);f.input.stderr=Buffer.from('2026-09-06T13:59:30Z\tWARN\t'+VENDOR_WARNING+'\n');seal(f);assert.throws(()=>run(f),{code:'ANALYSIS_DIAGNOSTIC'});});
test('legitimate case-normalized and percent-encoded Go PURL is accepted without changing module identity',()=>{const f=fixture(),name='github.com/Example/library',version='v1.2.3+incompatible',sum='h1:'+'b'.repeat(43)+'=';const report=JSON.parse(f.input.report),packages=report.Results[0].Packages;packages.push({ID:name+'@'+version,Name:name,Version:version,Identifier:{PURL:'pkg:golang/github.com/example/library@v1.2.3%2Bincompatible'},AnalyzedBy:'gobinary'});packages[0].DependsOn.push(name+'@'+version);f.input.report=Buffer.from(JSON.stringify(report));f.record.scan.packages=4;f.record.scan.inventorySha256=fingerprint(packages.toSorted((a,b)=>Buffer.compare(Buffer.from(canonicalForTest(a)),Buffer.from(canonicalForTest(b)))));f.input.buildInfo=Buffer.concat([f.input.buildInfo,Buffer.from(`\tdep\t${name}\t${version}\t${sum}\n`)]);graph(f,rows=>{rows[99]={ImportPath:name,Name:'library',Module:{Path:name,Version:version,Sum:sum}};rows[0].Imports[98]=name;});seal(f);assert.equal(run(f).status,'PASS_WITH_REVIEWED_NOT_AFFECTED');json(f,'report',x=>x.Results[0].Packages[3].Identifier.PURL='pkg:golang/github.com/example/library@'+version);seal(f);assert.throws(()=>run(f),{code:'PACKAGE_IDENTITY'});});
function canonicalForTest(x){if(Array.isArray(x))return JSON.stringify(x.map(v=>JSON.parse(canonicalForTest(v))));if(x&&typeof x==='object')return JSON.stringify(Object.fromEntries(Object.keys(x).sort().map(k=>[k,JSON.parse(canonicalForTest(x[k]))])));return JSON.stringify(x);}
