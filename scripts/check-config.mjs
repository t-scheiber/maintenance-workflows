import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
const root=path.resolve(import.meta.dirname,'..');
const walk=dir=>fs.readdirSync(dir,{withFileTypes:true}).flatMap(e=>{
 const name=path.join(dir,e.name);if(e.isSymbolicLink())throw Error('Control symlink rejected');
 return e.isDirectory()?(e.name==='.git'?[]:walk(name)):[name];
});
const files=walk(root);
for(const file of files.filter(f=>f.endsWith('.json')))JSON.parse(fs.readFileSync(file));
for(const file of files.filter(f=>f.endsWith('.mjs')))if(spawnSync(process.execPath,['--check',file],{stdio:'ignore',timeout:10000}).status!==0)throw Error('Invalid JavaScript control syntax');
for(const file of files.filter(f=>f.includes('/.github/workflows/')&&f.endsWith('.yml'))){
 const text=fs.readFileSync(file,'utf8');
 if(text.includes('secrets: inherit')||text.includes('pull_request_target:'))throw Error('Unreviewed workflow privilege');
 // Ignore literal scalar contents, including the caller template in the tested bootstrap.
 let scalarIndent=null;const yamlLines=[];
 for(const line of text.split('\n')){const indent=line.length-line.trimStart().length;if(scalarIndent!==null){if(!line.trim()||indent>scalarIndent)continue;scalarIndent=null;}const scalar=line.match(/^(\s*)[A-Za-z0-9_-]+:\s*[|>][-+]?\s*$/);if(scalar){scalarIndent=scalar[1].length;continue;}yamlLines.push(line);}
 for(const line of yamlLines.filter(l=>/^\s+(?:- )?uses:/.test(l)))if(!/^\s+(?:- )?uses: [A-Za-z0-9_.-]+\/[A-Za-z0-9_./-]+@[a-f0-9]{40}(?:\s*#.*)?$/.test(line))throw Error('Action must use an immutable commit');
}
console.log('Dependency-free public control syntax and immutable Action references verified');
