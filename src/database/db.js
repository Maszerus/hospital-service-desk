const Database = require('better-sqlite3');
const path = require('path');
const db = new Database(process.env.DB_PATH || path.join(__dirname, '../../data.sqlite'));

db.exec(`
CREATE TABLE IF NOT EXISTS lab_profile_baselines (user_id INTEGER PRIMARY KEY, display_name TEXT NOT NULL, email TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS lab_payloads (user_id INTEGER PRIMARY KEY, description TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, display_name TEXT, email TEXT);
CREATE TABLE IF NOT EXISTS tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT, description TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
`);
const addUser = db.prepare(
  'INSERT OR IGNORE INTO users(id,username,password,display_name,email) VALUES(?,?,?,?,?)',
);
addUser.run(1, 'student', 'student123', 'Jan Kowalski', 'jan.kowalski@example.test');
addUser.run(2, 'admin', 'admin123', 'Administrator LAB', 'admin@example.test');
if (db.prepare('SELECT COUNT(*) c FROM tickets').get().c === 0) {
  db.prepare('INSERT INTO tickets(user_id,title,description) VALUES(?,?,?)').run(
    1,
    'AMMS - problem testowy',
    'Przykładowe zgłoszenie laboratoryjne.',
  );
}
module.exports = db;
