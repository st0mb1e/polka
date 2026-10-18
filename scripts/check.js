import { readdir } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';

for (const directory of ['scripts', 'src', 'public', 'test']) {
  for (const file of await readdir(new URL(`../${directory}/`, import.meta.url))) {
    if (!file.endsWith('.js')) continue;
    const result = spawnSync(process.execPath, ['--check', `${directory}/${file}`], { stdio: 'inherit' });
    if (result.status !== 0) process.exit(result.status ?? 1);
  }
}
console.log('Синтаксис JavaScript проверен.');
