// Starts every node-*.json in ./devnet as a child process and prefixes its output.
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, '..', 'devnet');
if (!fs.existsSync(root)) {
  console.error('No devnet found. Run: npm run devnet:init');
  process.exit(1);
}

const configs = fs.readdirSync(root).filter((f) => /^node-\d+\.json$/.test(f)).sort();
const children = configs.map((file) => {
  const name = file.replace('.json', '');
  const child = spawn(process.execPath, [path.join(here, '..', 'src', 'cli.js'), 'node', '--config', path.join(root, file)]);
  for (const stream of [child.stdout, child.stderr]) {
    stream.on('data', (data) => {
      for (const line of data.toString().trimEnd().split('\n')) console.log(`[${name}] ${line}`);
    });
  }
  child.on('exit', (code) => console.log(`[${name}] exited with code ${code}`));
  return child;
});

const stop = () => children.forEach((c) => c.kill('SIGTERM'));
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
