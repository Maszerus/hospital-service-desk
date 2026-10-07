const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const ejs = require('ejs');

test('szablony HTML zachowują poprawną składnię EJS po formatowaniu', () => {
  const viewsDirectory = path.join(__dirname, '../src/views');
  const templates = fs
    .readdirSync(viewsDirectory, { recursive: true })
    .filter((file) => file.endsWith('.html'));

  for (const template of templates) {
    const filename = path.join(viewsDirectory, template);
    const source = fs.readFileSync(filename, 'utf8');

    assert.doesNotThrow(() => ejs.compile(source, { filename }), template);
  }
});
