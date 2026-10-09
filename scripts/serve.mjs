import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { realpath, stat, open } from 'node:fs/promises';
import { once } from 'node:events';

const argv = process.argv.slice(2);
let root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../web');
let port = 4174;
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === '--root' && argv[i+1]) root = path.resolve(argv[++i]);
  else if (argv[i] === '--port' && argv[i+1] && /^\d+$/.test(argv[i+1])) port = Number(argv[++i]);
  else throw new Error('Usage: node scripts/serve.mjs [--root web] [--port 4174]');
}
if (!Number.isSafeInteger(port) || port < 0 || port > 65535) throw new Error('Port must be an integer from 0 to 65535.');
root = await realpath(root);
if (!(await stat(root)).isDirectory()) throw new Error('Static site root must be a directory.');
const types = new Map([['.html','text/html; charset=utf-8'], ['.js','text/javascript; charset=utf-8'], ['.css','text/css; charset=utf-8'], ['.json','application/json; charset=utf-8'], ['.png','image/png'], ['.jpg','image/jpeg'], ['.svg','image/svg+xml'], ['.txt','text/plain; charset=utf-8'], ['.ico','image/x-icon']]);
const headers = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; worker-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store',
  'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Resource-Policy': 'same-origin'
};
const contained = p => p === root || p.startsWith(root + path.sep);
const server = http.createServer(async (request, response) => {
  for (const [key,value] of Object.entries(headers)) response.setHeader(key,value);
  const fail = (status, text) => { response.writeHead(status, {'Content-Type':'text/plain; charset=utf-8'}); response.end(request.method==='HEAD' ? undefined : text); };
  if (!['GET','HEAD'].includes(request.method ?? '')) { response.setHeader('Allow','GET, HEAD'); fail(405,'Only static GET and HEAD requests are accepted.'); return; }
  let pathname;
  try { pathname = decodeURIComponent((request.url ?? '/').split('?')[0]); }
  catch { fail(400,'Invalid URL encoding.'); return; }
  if (/[\x00-\x1f\x7f]/.test(pathname)) { fail(400,'Invalid path.'); return; }
  if (!pathname.startsWith('/') || pathname.includes('\\') || pathname.split('/').includes('..') || pathname.split('/').includes('.')) { fail(404,'File not found.'); return; }
  // Use one portable path profile: Windows alternate streams and aliases are never static assets.
  if (pathname.split('/').slice(1).some(segment => !segment || /[:]/.test(segment) || /[. ]$/.test(segment) || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(segment))) {
    if (pathname !== '/') { fail(404,'File not found.'); return; }
  }
  const relative = pathname==='/' ? 'index.html' : pathname.slice(1);
  const target = path.resolve(root, relative);
  if (!contained(target)) { fail(404,'File not found.'); return; }
  let handle;
  try {
    const actual = await realpath(target);
    if (!contained(actual)) { fail(404,'File not found.'); return; }
    handle = await open(actual, 'r');
    const info = await handle.stat();
    if (!info.isFile() || info.size > 128*1024*1024) { await handle.close(); handle=undefined; fail(404,'File not found.'); return; }
    response.writeHead(200, {'Content-Type':types.get(path.extname(actual).toLowerCase()) ?? 'application/octet-stream', 'Content-Length':info.size});
    if(request.method==='HEAD') { await handle.close(); handle=undefined; response.end(); return; }
    const stream = handle.createReadStream({ autoClose: true }); handle=undefined;
    stream.on('error', () => response.destroy()); response.on('close', () => stream.destroy()); stream.pipe(response);
  } catch {
    if(handle) await handle.close().catch(()=>{});
    if(response.headersSent) response.destroy(); else fail(404,'File not found.');
  }
});
server.requestTimeout=10000; server.headersTimeout=10000;
server.listen(port,'127.0.0.1'); await once(server,'listening');
console.log(JSON.stringify({status:'listening',url:'http://127.0.0.1:'+server.address().port}));
const shutdown=()=>server.close(()=>process.exit(0));
process.on('SIGINT',shutdown); process.on('SIGTERM',shutdown);
