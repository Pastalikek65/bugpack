import { readFile, writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const lockBytes = await readFile(path.join(root,'package-lock.json'));
const lock = JSON.parse(lockBytes.toString('utf8'));
const runtime = ['react','react-dom','scheduler','fflate','vite'];
const out = path.join(root,'third_party'); await mkdir(path.join(out,'licenses'),{recursive:true});
const notices = [];
for(const name of runtime) {
  const entry = lock.packages['node_modules/'+name];
  if(!entry?.version || !entry.integrity || !entry.resolved || !entry.license) throw new Error('Missing pinned dependency provenance for '+name);
  const bytes=await readFile(path.join(root,'node_modules',name,name==='vite'?'LICENSE.md':'LICENSE'));
  const file=name+'.LICENSE.txt'; await writeFile(path.join(out,'licenses',file),bytes);
  notices.push({ name,version:entry.version,license:entry.license,resolved:entry.resolved,integrity:entry.integrity,notice:file,noticeSha256:createHash('sha256').update(bytes).digest('hex'),role:name==='vite'?'build-generated asset loading helper':'bundled browser runtime' });
}
const packages=Object.entries(lock.packages).filter(([name])=>name).map(([name,e])=>({path:name,version:e.version,license:e.license??'not declared in lockfile',resolved:e.resolved??null,integrity:e.integrity??null,development:e.dev===true,optional:e.optional===true}));
await writeFile(path.join(out,'dependencies.json'),JSON.stringify({schemaVersion:1,packageLockSha256:createHash('sha256').update(lockBytes).digest('hex'),scope:'npm lockfile inventory including optional packages; not every optional package is installed on each platform',runtimeComponents:notices,packages},null,2)+'\n');
await writeFile(path.join(out,'README.md'),'# Third-party notices\n\nThe browser bundle includes React, React DOM, Scheduler and fflate; their original MIT licenses are in licenses/. The Vite MIT notice is included for its generated loading helper. dependencies.json binds versions, registry integrity and license declarations to the npm lockfile. The full lockfile inventory includes development and optional platform packages; it does not imply that every optional dependency is installed or distributed. Node.js and Chromium are user-provided runtimes and are not included in the static application archives.\n');
console.log(JSON.stringify({status:'notices-generated',runtimeNotices:notices.length,lockPackages:packages.length}));
