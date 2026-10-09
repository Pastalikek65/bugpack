import { readFile, writeFile, mkdir, readdir, stat, cp, chmod } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { zipSync } from 'fflate';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const pkg=JSON.parse(await readFile(path.join(root,'package.json'),'utf8'));
if(!/^\d+\.\d+\.\d+$/.test(pkg.version)) throw new Error('Package version must be stable numeric semver.');
if(!['win32','linux'].includes(process.platform) || process.arch!=='x64') throw new Error('Package qualification targets Windows/Linux x64.');
const release=path.join(root,'release'); await mkdir(release,{recursive:true});
const suffix=process.platform==='win32'?'win-x64':'linux-x64'; const dirname='bugpack-'+pkg.version+'-'+suffix;
const staging=path.join(release,dirname);
try { await stat(staging); throw new Error('Staging already exists; use a fresh working directory rather than replacing retained evidence.'); } catch(e) { if(e.code!=='ENOENT') throw e; }
await mkdir(staging);
for(const [source,target] of [['dist','web'],['third_party','third_party'],['examples','examples']]) await cp(path.join(root,source),path.join(staging,target),{recursive:true,errorOnExist:true});
for(const name of ['README.md','LICENSE','NOTICE','SECURITY.md']) await cp(path.join(root,name),path.join(staging,name));
await mkdir(path.join(staging,'scripts')); await cp(path.join(root,'scripts/serve.mjs'),path.join(staging,'scripts/serve.mjs'));
await mkdir(path.join(staging,'docs')); for(const name of ['quickstart.tr.md','support.md']) await cp(path.join(root,'docs',name),path.join(staging,'docs',name));
await writeFile(path.join(staging,'package.json'),JSON.stringify({name:'bugpack-portable',version:pkg.version,private:true,type:'module',license:'Apache-2.0',engines:{node:'^24.0.0'},scripts:{start:'node scripts/serve.mjs'}},null,2)+'\n');
await writeFile(path.join(staging,'start.cmd'),'@echo off\r\nnode "%~dp0scripts\\serve.mjs" --root "%~dp0web" --port 4174\r\n');
await writeFile(path.join(staging,'start.sh'),'#!/bin/sh\nset -eu\napp_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\nexec node "$app_dir/scripts/serve.mjs" --root "$app_dir/web" --port 4174\n');
await chmod(path.join(staging,'start.sh'),0o755);
let archive;
if(process.platform==='win32') {
 const entries=Object.create(null);
 async function visit(dir,relative='') { for(const e of await readdir(dir,{withFileTypes:true})) { const rel=relative+e.name; const absolute=path.join(dir,e.name); if(e.isDirectory()) await visit(absolute,rel+'/'); else if(e.isFile()) entries[dirname+'/'+rel]=new Uint8Array(await readFile(absolute)); else throw new Error('Package staging contains unsupported file type.'); } }
 await visit(staging); archive=path.join(release,dirname+'.zip'); await writeFile(archive,zipSync(entries,{level:6}));
} else {
 archive=path.join(release,dirname+'.tar.gz');execFileSync('tar',['-czf',archive,'-C',release,dirname],{stdio:'inherit'});
}
const bytes=await readFile(archive); const sha256=createHash('sha256').update(bytes).digest('hex'); await writeFile(path.join(release,'SHA256SUMS.txt'),sha256+'  '+path.basename(archive)+'\n');
console.log(JSON.stringify({status:'packaged',version:pkg.version,platform:process.platform+'/'+process.arch,path:archive,bytes:bytes.length,sha256}));
