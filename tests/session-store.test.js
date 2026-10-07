const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { promisify } = require('node:util');
const Database = require('better-sqlite3');
const { SessionStore, SESSION_DURATION } = require('../src/database/session-store');

test('sesja przetrwa ponowne otwarcie bazy, wygasa i jest usuwana po wylogowaniu', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hsd-session-'));
  const databasePath = path.join(directory, 'sessions.sqlite');
  let database = new Database(databasePath);

  try {
    let store = new SessionStore(database);
    const session = {
      userId: 1,
      cookie: { expires: new Date(Date.now() + SESSION_DURATION).toISOString() },
    };
    await promisify(store.set).call(store, 'remembered-session', session);
    database.close();

    database = new Database(databasePath);
    store = new SessionStore(database);
    const get = promisify(store.get).bind(store);
    assert.deepEqual(await get('remembered-session'), session);

    await promisify(store.destroy).call(store, 'remembered-session');
    assert.equal(await get('remembered-session'), null);

    await promisify(store.set).call(store, 'expired-session', {
      ...session,
      cookie: { expires: new Date(Date.now() - 1000).toISOString() },
    });
    assert.equal(await get('expired-session'), null);
    assert.equal(database.prepare('SELECT COUNT(*) AS count FROM sessions').get().count, 0);
  } finally {
    if (database.open) database.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
