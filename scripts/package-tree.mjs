import { lstat, readdir } from 'node:fs/promises';
import path from 'node:path';

export async function assertPackageTree(root) {
  let count = 0, bytes = 0;
  async function visit(absolute) {
    const info = await lstat(absolute);
    if (info.isSymbolicLink()) throw new Error('Package inputs must not contain symbolic links or junctions.');
    if (info.isDirectory()) {
      for (const name of await readdir(absolute)) {
        if (!name || /[\\/:\x00-\x1f\x7f]/.test(name) || /[. ]$/.test(name) || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(name)) throw new Error('Package input has a non-portable filename.');
        await visit(path.join(absolute, name));
      }
    } else if (info.isFile()) {
      count++; bytes += info.size;
      if (count > 1000 || bytes > 128 * 1024 * 1024) throw new Error('Package input exceeds its file or byte budget.');
    } else throw new Error('Package input contains an unsupported filesystem object.');
  }
  await visit(root);
  return { files: count, bytes };
}
