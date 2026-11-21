// Converts a stopped node's plain block files (.json) into the compact format (.cb).
// Usage: node scripts/compact-blocks.js <dataDir> [<dataDir> ...]   (the node must be stopped)
import path from 'node:path';
import { BlockStore } from '../src/blockstore.js';

const dirs = process.argv.slice(2);
if (!dirs.length) { console.error('usage: node scripts/compact-blocks.js <dataDir> ...'); process.exit(1); }
for (const dir of dirs) {
  const store = new BlockStore(path.join(dir, 'blocks'));
  store.compact({ log: (m) => console.log(`${dir}: ${m}`) });
}
