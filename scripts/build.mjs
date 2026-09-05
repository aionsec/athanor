import { spawnSync } from 'node:child_process';
import { chmodSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const dist = join(root, 'dist');
const windows = process.platform === 'win32';

rmSync(dist, { recursive: true, force: true });

// npm's Windows compiler shim is a .cmd file, so it needs the native command
// interpreter. Keep its path relative to cwd: no checkout path enters shell text.
const compiler = windows ? 'cmd.exe' : join(root, 'node_modules', '.bin', 'tsc');
const args = windows
  ? ['/d', '/c', 'node_modules\\.bin\\tsc.cmd', '-p', 'tsconfig.build.json']
  : ['-p', 'tsconfig.build.json'];
const result = spawnSync(compiler, args, { cwd: root, stdio: 'inherit' });

if (result.error) {
  console.error(`build: ${result.error.message}`);
  process.exit(1);
}
if (result.status !== 0) process.exit(result.status ?? 1);

if (!windows) {
  const cli = join(dist, 'cli.js');
  chmodSync(cli, statSync(cli).mode | 0o111);
}
