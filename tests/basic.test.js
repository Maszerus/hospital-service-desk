const test = require('node:test');
const assert = require('node:assert/strict');
const { escapeHtml } = require('../src/security/render');
test('secure renderer escapes HTML', () =>
  assert.equal(escapeHtml('<script>alert(1)</script>'), '&lt;script&gt;alert(1)&lt;/script&gt;'));
