// Trusted public wrapper. Source authority comes only from protected code-owned policy.
import fs from 'node:fs';
import path from 'node:path';
import {parseJson} from './native-admission.mjs';
import {admitSourceTools,validateSourceAuthority} from './native-source-authority.mjs';
export function sourcePolicy(){return parseJson(fs.readFileSync(new URL('./policy/source-authority.json',import.meta.url)),'record');}
export function pendingPolicy(){return parseJson(fs.readFileSync(new URL('./policy/native-scanners.pending.json',import.meta.url)),'record');}
export function admitSourceScanners(directory,{authority=sourcePolicy(),pending=pendingPolicy(),env=process.env,now=Date.now()}={}){
 if(['GH_TOKEN','GITHUB_TOKEN','OPENROUTER_API_KEY','MAINTENANCE_APP_PRIVATE_KEY','ACTIONS_RUNTIME_TOKEN'].some(key=>env[key]))throw Error('Source admission requires a credential-free environment');
 validateSourceAuthority(authority,pending);
 const ids={'t-scheiber/maintenance-workflows':'1359178236','t-scheiber/AK_WeatherApp':'755321462','t-scheiber/ScheiberVueAppAbgabe':'755319788'};
 if(!Object.hasOwn(ids,env.GITHUB_REPOSITORY)||ids[env.GITHUB_REPOSITORY]!==env.GITHUB_REPOSITORY_ID||env.GITHUB_REPOSITORY_OWNER_ID!=='66697291'||env.PUBLIC_REPOSITORY_PRIVATE!=='false')throw Error('Public source identity differs');
 if(!/^[1-9][0-9]{0,2}$/.test(env.GITHUB_RUN_ATTEMPT||''))throw Error('Public source run attempt differs');
 const run={repository:env.GITHUB_REPOSITORY,sourceRevision:env.GITHUB_SHA,toolsRevision:env.PUBLIC_TOOLS_REF,runId:env.GITHUB_RUN_ID,runAttempt:Number(env.GITHUB_RUN_ATTEMPT),now};
 const result=admitSourceTools(directory,authority,pending,run),receipts={},binaries={};
 for(const receipt of result.tools){receipts[receipt.tool]=receipt;binaries[receipt.tool]=path.join(directory,receipt.tool,'binary');}
 return {...result,controlPlaneCommit:result.hostedSourceCommit,receipts,binaries};
}
if(process.argv[1]&&path.resolve(process.argv[1])===import.meta.filename){
 if(process.argv.length!==2||!process.env.RUNNER_TEMP||!path.isAbsolute(process.env.RUNNER_TEMP))throw Error('Unexpected source admission arguments');
 const result=admitSourceScanners(path.join(process.env.RUNNER_TEMP,'native-bundle-verification/fresh'));
 console.log(JSON.stringify({status:result.status,controlPlaneCommit:result.controlPlaneCommit}));
}
