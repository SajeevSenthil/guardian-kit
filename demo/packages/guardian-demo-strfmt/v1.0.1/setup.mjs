// DEMO ONLY - HARMLESS. Imitates the *shape* of the 2025-2026 npm worm droppers
// ("preinstall": "node setup.mjs" + a large encoded payload file) so the Guardian's
// version-to-version capability diff has something to find. It makes NO network
// calls, spawns NO processes and reads NO secret values. It writes one marker file.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const RUNTIME_URL = 'https://runtime.example.invalid/install';   // never contacted
const payload = path.join(path.dirname(new URL(import.meta.url).pathname), 'math_init.js');
const size = fs.existsSync(payload) ? fs.statSync(payload).size : 0;
fs.writeFileSync(
  path.join(os.tmpdir(), 'guardian-demo-preinstall.txt'),
  `DEMO: preinstall executed at ${new Date().toISOString()}; payload file is ${size} bytes of ` +
  `encoded lorem ipsum and was NOT executed; ${RUNTIME_URL} was NOT contacted.\n`
);
