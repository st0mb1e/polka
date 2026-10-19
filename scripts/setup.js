import { randomBytes } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

export const envPath = fileURLToPath(new URL('../.env', import.meta.url));

export async function setup() {
  const template = await readFile(new URL('../.env.example', import.meta.url), 'utf8');
  const contents = template.replace(
    /^(CLIENT_SECRET|SESSION_SECRET|AUTH_COOKIE_SECRET|DEMO_PASSWORD)=$/gm,
    (_, key) => `${key}=${randomBytes(32).toString('base64url')}`,
  );
  try {
    await writeFile(envPath, contents, { flag: 'wx', mode: 0o600 });
    console.log('Создан .env. Добавьте GOOGLE_CLIENT_ID и GOOGLE_CLIENT_SECRET для входа через Google.');
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
    console.log('Используется существующий .env.');
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await setup();
