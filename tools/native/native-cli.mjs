import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
import {admitNativeEvidence} from './native-evidence.mjs';
import {parseJson,reject} from './native-admission.mjs';
const files={report:'report.json',stderr:'stderr.log',graph:'graph.jsonl',manifest:'manifest.json',buildInfo:'build-info.txt',pclntab:'pclntab.json',advisory:'advisory.json',execution:'execution.json',provenance:'provenance.json',binary:'binary'};
// The registry is part of trusted control code, never read from the evidence mount.
// This scratch CLI deliberately loads only pending records and cannot activate one.
export function main(args){try{if(args.length!==4||args[0]!=='--tool'||args[2]!=='--evidence-root'||!['gitleaks','osv-scanner','trivy'].includes(args[1]))reject('CLI_ARGUMENTS');const registry=parseJson(fs.readFileSync(new URL('./policy/native-scanners.pending.json',import.meta.url)),'record');if(registry.state!=='pending-only'||Object.values(registry.records).some(x=>x.record?.state!=='pending'))reject('PENDING_REGISTRY');const selected=registry.records[args[1]];if(!selected)reject('CLI_TOOL');const receipt=admitNativeEvidence(args[3],files,selected.record,{recordSha256:selected.recordSha256,now:Date.now()});process.stdout.write(JSON.stringify(receipt)+'\n');return receipt.status==='PASS_WITH_REVIEWED_NOT_AFFECTED'?0:1;}catch(error){process.stderr.write('Native scanner admission rejected: '+(error.code&&/^[A-Z_]{1,60}$/.test(error.code)?error.code:'EVIDENCE_FAILURE')+'\n');return 1;}}
if(process.argv[1]===fileURLToPath(import.meta.url))process.exitCode=main(process.argv.slice(2));
