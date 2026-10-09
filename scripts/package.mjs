import { readFile, writeFile, mkdir, readdir, lstat, realpath, cp, chmod } from 'node:fs/promises';
import { assertPackageTree } from './package-tree.mjs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { zipSync } from 'fflate';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const pkg=JSON.parse(await readFile(path.join(root,'package.json'),'utf8'));
if(!/^\d+\.\d+\.\d+$/.test(pkg.version)) throw new Error('Package version must be stable numeric semver.');
if(!['win32','linux'].includes(process.platform) || process.arch!=='x64') throw new Error('Package qualification targets Windows/Linux x64.');
const args=process.argv.slice(2);
if(args.length && (args.length!==2 || args[0]!=='--output')) throw new Error('Usage: node scripts/package.mjs [--output fresh-directory]');
const requested=args.length?path.resolve(args[1]):path.join(root,'release');
try { if((await lstat(requested)).isSymbolicLink())throw new Error('Package output must not be a symbolic link or junction.'); } catch(error){if(error.code!=='ENOENT')throw error;}
let existing=requested;const tail=[];
while(true){try{await lstat(existing);break;}catch(error){if(error.code!=='ENOENT')throw error;tail.unshift(path.basename(existing));existing=path.dirname(existing);}}
const release=path.join(await realpath(existing),...tail);
const normalized=value=>process.platform==='win32'?value.toLowerCase():value;
for(const name of ['dist','third_party','examples','docs','scripts','src','tests']){
 const input=normalized(path.join(await realpath(root),name)), output=normalized(release);
 if(output===input||output.startsWith(input+path.sep)||input.startsWith(output+path.sep))throw new Error('Package output must not overlap project inputs. Use a fresh release directory.');
}
await mkdir(release,{recursive:true});
if((await lstat(release)).isSymbolicLink()) throw new Error('Package output must be an actual directory, not a link.');
const suffix=process.platform==='win32'?'win-x64':'linux-x64'; const dirname='bugpack-'+pkg.version+'-'+suffix;
const staging=path.join(release,dirname);
const archive=path.join(release,dirname+(process.platform==='win32'?'.zip':'.tar.gz'));
for(const target of [staging,archive,path.join(release,'SHA256SUMS.txt')]) {
 try { await lstat(target); throw new Error('Package output already exists; use --output with a fresh directory.'); } catch(e) { if(e.code!=='ENOENT') throw e; }
}
const shippedDocs=['quickstart.tr.md','support.md','cli.md','architecture.md','roadmap.md','verification.md','performance.md'];
for(const source of ['dist','third_party','examples','README.md','LICENSE','NOTICE','SECURITY.md',...shippedDocs.map(name=>'docs/'+name),'scripts/serve.mjs']) await assertPackageTree(path.join(root,source));
await mkdir(staging);
for(const [source,target] of [['dist','web'],['third_party','third_party'],['examples','examples']]) await cp(path.join(root,source),path.join(staging,target),{recursive:true,errorOnExist:true,filter:src=>source!=='dist'||path.relative(path.join(root,'dist'),src).split(path.sep)[0]!=='cli'});
await cp(path.join(root,'dist/cli'),path.join(staging,'cli'),{recursive:true,errorOnExist:true});
for(const name of ['README.md','LICENSE','NOTICE','SECURITY.md']) await cp(path.join(root,name),path.join(staging,name));
await mkdir(path.join(staging,'scripts')); await cp(path.join(root,'scripts/serve.mjs'),path.join(staging,'scripts/serve.mjs'));
await mkdir(path.join(staging,'docs')); for(const name of shippedDocs) await cp(path.join(root,'docs',name),path.join(staging,'docs',name));
await writeFile(path.join(staging,'package.json'),JSON.stringify({name:'bugpack-portable',version:pkg.version,private:true,type:'module',license:'Apache-2.0',engines:{node:'^24.0.0'},bin:{bugpack:'cli/bugpack.mjs'},scripts:{start:'node scripts/serve.mjs',doctor:'node cli/bugpack.mjs doctor'}},null,2)+'\n');
await chmod(path.join(staging,'cli/bugpack.mjs'),0o755);
await writeFile(path.join(staging,'start.cmd'),'@echo off\r\nnode "%~dp0scripts\\serve.mjs" --root "%~dp0web" --port 4174\r\n');
await writeFile(path.join(staging,'start.sh'),'#!/bin/sh\nset -eu\napp_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\nexec node "$app_dir/scripts/serve.mjs" --root "$app_dir/web" --port 4174\n');
await chmod(path.join(staging,'start.sh'),0o755);
await assertPackageTree(staging);
if(process.platform==='win32') {
 const entries=Object.create(null);
 async function visit(dir,relative='') { for(const e of await readdir(dir,{withFileTypes:true})) { const rel=relative+e.name; const absolute=path.join(dir,e.name); if(e.isDirectory()) await visit(absolute,rel+'/'); else if(e.isFile()) entries[dirname+'/'+rel]=new Uint8Array(await readFile(absolute)); else throw new Error('Package staging contains unsupported file type.'); } }
 await visit(staging); await writeFile(archive,zipSync(entries,{level:6}),{flag:'wx'});
} else {
 const tarBytes=execFileSync('tar',['-czf','-','-C',release,dirname],{maxBuffer:32*1024*1024});await writeFile(archive,tarBytes,{flag:'wx'});
}
const bytes=await readFile(archive); const sha256=createHash('sha256').update(bytes).digest('hex'); await writeFile(path.join(release,'SHA256SUMS.txt'),sha256+'  '+path.basename(archive)+'\n',{flag:'wx'});
console.log(JSON.stringify({status:'packaged',version:pkg.version,platform:process.platform+'/'+process.arch,path:archive,bytes:bytes.length,sha256}));
