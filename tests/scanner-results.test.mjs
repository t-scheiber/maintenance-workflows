import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {sourceFindings} from '../tools/static-pages/scanner-results.mjs';
const semgrep=path=>({version:'1.176.0',paths:{scanned:[path]},errors:[],results:[{check_id:'synthetic.rule',path,start:{line:1},extra:{message:'raw scanner message must not be projected',lines:'raw source must not be projected'}}]});
test('source scanner projection contains only validated locations and retains all findings',()=>{
 assert.deepEqual(sourceFindings('semgrep',semgrep('app.js')),[{rule:'synthetic.rule',path:'app.js',line:1}]);
 assert.deepEqual(sourceFindings('gitleaks',[{RuleID:'synthetic-rule',File:'app.js',StartLine:4,Secret:'synthetic-only',Match:{untrusted:'content'}}]),[{rule:'synthetic-rule',path:'app.js',line:4}]);
 assert.throws(()=>sourceFindings('unknown',{}));
});
test('known credential-like scanner metadata is rejected before any location output',()=>{
 const marker='gh'+'p_'+'synthetic';
 assert.throws(()=>sourceFindings('semgrep',semgrep(marker+'.js')),/Unsafe/);
 assert.throws(()=>sourceFindings('osv',{results:[{source:{path:'lock',type:'lockfile'},packages:[{package:{name:'example',version:'1',ecosystem:'npm'},vulnerabilities:[{id:marker}]}]}]}),/Unsafe/);
 assert.throws(()=>sourceFindings('trivy',{SchemaVersion:2,ArtifactType:'filesystem',ArtifactName:'.',Results:[{Class:'config',Type:'dockerfile',Target:marker,MisconfSummary:{Successes:0,Failures:1},Misconfigurations:[{ID:'AVD-SYNTHETIC',Severity:'HIGH'}]}]}),/Unsafe/);
 assert.throws(()=>sourceFindings('gitleaks',[{RuleID:'synthetic-rule',File:marker,StartLine:1}]));
});
test('malformed nested reports and incomplete analysis cannot report a clean source gate',()=>{
 for(const [scanner,data] of [['osv',{results:[{}]}],['semgrep',{...semgrep('app.js'),errors:[{message:'raw detail'}]}],['trivy',{SchemaVersion:2,ArtifactType:'filesystem',ArtifactName:'.',Results:[{}]}]])assert.throws(()=>sourceFindings(scanner,data));
});
test('trusted launcher validates all scanner results and bounds report reads',()=>{
 const code=fs.readFileSync(new URL('../tools/static-pages/source-scanner.mjs',import.meta.url),'utf8');
 assert.ok(code.includes('findings=sourceFindings(scanner,data)'));
 assert.ok(code.indexOf('stat.size>16*1024*1024')<code.indexOf('raw=fs.readFileSync'));
 assert.ok(code.includes('!run.error'));
 assert.ok(code.includes('status===0'));
 assert.ok(code.includes('discardReport();'));
 assert.ok(code.includes('fs.constants.O_NOFOLLOW'));
 assert.ok(!code.includes('writeFileSync(filename'));
 assert.ok(!code.includes('console.log(data)')&&!code.includes('console.log(raw)'));
});
