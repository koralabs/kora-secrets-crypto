// Copy non-TS assets (the fingerprint lookup tables) that tsc doesn't emit into lib/.
import { cpSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const from = resolve(root, 'src/data');
const to = resolve(root, 'lib/data');
if (existsSync(from)) {
  cpSync(from, to, { recursive: true });
  console.log(`copied src/data → lib/data`);
}
