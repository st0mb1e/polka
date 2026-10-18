import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

export function shelfUserKey(provider, subject) {
  return createHash('sha256').update(JSON.stringify([provider, subject])).digest('hex');
}

export class ShelfStore {
  #pending = Promise.resolve();

  constructor(filename = fileURLToPath(new URL('../.data/shelves.json', import.meta.url))) {
    this.filename = filename;
  }

  async #load() {
    try {
      const data = JSON.parse(await readFile(this.filename, 'utf8'));
      if (data.version !== 1 || !data.users || typeof data.users !== 'object' || Array.isArray(data.users)) {
        throw new Error('Invalid shelf data');
      }
      return data;
    } catch (error) {
      if (error.code === 'ENOENT') return { version: 1, users: {} };
      throw error;
    }
  }

  async get(userKey) {
    await this.#pending;
    const data = await this.#load();
    return { ...(data.users[userKey] ?? {}) };
  }

  set(userKey, bookId, status) {
    const operation = this.#pending.then(async () => {
      const data = await this.#load();
      const shelf = { ...(data.users[userKey] ?? {}) };
      if (status === null) delete shelf[bookId];
      else shelf[bookId] = status;
      data.users[userKey] = shelf;
      await mkdir(dirname(this.filename), { recursive: true, mode: 0o700 });
      const temporary = `${this.filename}.${randomUUID()}.tmp`;
      try {
        await writeFile(temporary, `${JSON.stringify(data, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
        await rename(temporary, this.filename);
      } finally {
        await unlink(temporary).catch((error) => { if (error.code !== 'ENOENT') throw error; });
      }
      return shelf;
    });
    // One failed operation must not prevent later writes from being retried.
    this.#pending = operation.catch(() => {});
    return operation;
  }
}
