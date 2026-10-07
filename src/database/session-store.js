const { Store } = require('express-session');

const SESSION_DURATION = 30 * 24 * 60 * 60 * 1000;

class SessionStore extends Store {
  constructor(database) {
    super();
    this.database = database;
    database.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        data TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      );
    `);
    database.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(Date.now());
  }

  get(id, callback) {
    try {
      const row = this.database.prepare('SELECT data, expires_at FROM sessions WHERE id=?').get(id);
      if (!row) return callback(null, null);
      if (row.expires_at <= Date.now()) return this.destroy(id, (error) => callback(error, null));
      callback(null, JSON.parse(row.data));
    } catch (error) {
      callback(error);
    }
  }

  set(id, session, callback = () => {}) {
    try {
      const expiresAt = session.cookie.expires
        ? new Date(session.cookie.expires).getTime()
        : Date.now() + SESSION_DURATION;

      this.database
        .prepare('INSERT OR REPLACE INTO sessions(id,data,expires_at) VALUES(?,?,?)')
        .run(id, JSON.stringify(session), expiresAt);
      callback(null);
    } catch (error) {
      callback(error);
    }
  }

  touch(id, session, callback) {
    this.set(id, session, callback);
  }

  destroy(id, callback = () => {}) {
    try {
      this.database.prepare('DELETE FROM sessions WHERE id=?').run(id);
      callback(null);
    } catch (error) {
      callback(error);
    }
  }
}

module.exports = { SessionStore, SESSION_DURATION };
