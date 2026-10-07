const test = require('node:test');
const assert = require('node:assert/strict');
process.env.DB_PATH = ':memory:';
process.env.APP_MODE = 'vulnerable';
const app = require('../app');
const db = require('../src/database/db');
test('Stored XSS, CSRF i nagłówki BEFORE/AFTER oraz legalne formularze', async () => {
  const server = app.listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  let cookie;
  const send = async (path, body) => {
    const r = await fetch(base + path, {
      method: body === undefined ? 'GET' : 'POST',
      headers: {
        ...(cookie ? { Cookie: cookie } : {}),
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: 'manual',
    });
    if (r.headers.get('set-cookie')) cookie = r.headers.get('set-cookie').split(';')[0];
    return r;
  };
  try {
    assert.equal((await send('/lab/test-info')).status, 302);
    assert.equal(
      (await send('/login', { username: 'student', password: 'student123' })).status,
      302,
    );
    const baseline = db.prepare('SELECT display_name,email FROM users WHERE id=1').get();
    const spec = await (await send('/lab/xss-info')).json();
    assert.ok(spec.script.includes('parent.document'));
    assert.equal(spec.changes.length, 5);
    assert.equal((await send('/lab/xss-probe', { description: 'INNY PAYLOAD' })).status, 400);
    const payload = await (await send('/lab/xss-probe', { description: spec.payload })).json();
    assert.equal(payload.stored, true);
    assert.equal(payload.storage.record.description, spec.payload);
    assert.equal(payload.storage.table, 'lab_payloads');
    assert.equal(
      db.prepare('SELECT description FROM lab_payloads WHERE user_id=1').get().description,
      payload.payload,
    );
    assert.match(await (await send('/lab/xss-frame')).text(), /<img src=/);
    assert.doesNotMatch(await (await send('/lab/xss-frame?baseline=1')).text(), /<img src=/);
    const instructions = await send('/instructions');
    assert.equal(instructions.status, 200);
    assert.match(await instructions.text(), /Instrukcja do|Postman/);
    for (const kind of ['postman', 'http-env', 'https-env', 'manual', 'curl'])
      assert.equal((await send('/lab/download/' + kind)).status, 200);
    assert.equal((await send('/lab/download/toString')).status, 404);
    const candidates = [];
    for (const csrfToken of [undefined, 'INVALID-TOKEN']) {
      const candidate = await (await send('/lab/profile-candidate')).json();
      candidates.push(candidate);
      const r = await send('/lab/profile-probe', { ...candidate, csrfToken });
      assert.equal(r.status, 200);
      const j = await r.json();
      assert.equal(j.changed, true);
      assert.equal(j.persisted, true);
      assert.equal(j.autoRestored, false);
      const state = await (await send('/lab/profile-state')).json();
      assert.deepEqual(state.profile, candidate);
      assert.deepEqual(state.initialProfile, baseline);
      const profileHtml = await (await send('/profile')).text();
      assert.ok(profileHtml.includes(candidate.display_name));
      assert.ok(profileHtml.includes(candidate.email));
    }
    assert.notEqual(candidates[0].display_name, candidates[1].display_name);
    assert.notEqual(candidates[0].email, candidates[1].email);
    assert.equal((await send('/lab/profile-restore', {})).status, 403);
    assert.equal((await send('/lab/profile-restore', { csrfToken: 'INVALID' })).status, 403);
    const attackedProfile = await (await send('/lab/profile-state')).json();
    const modeResponse = await send('/lab/mode', { mode: 'secure' });
    assert.equal(modeResponse.status, 200);
    assert.match(modeResponse.headers.get('set-cookie'), /HttpOnly/);
    assert.match(modeResponse.headers.get('set-cookie'), /SameSite=Strict/);
    const after = await send('/lab/test-info');
    const i = await after.json();
    assert.ok(after.headers.get('content-security-policy'));
    const frame = await send('/lab/xss-frame');
    assert.match(await frame.text(), /&lt;img/);
    assert.equal(
      (
        await send('/lab/profile-probe', {
          display_name: 'REJECTED',
          email: 'rejected@example.test',
        })
      ).status,
      403,
    );
    assert.equal(
      (
        await send('/lab/profile-probe', {
          display_name: 'REJECTED',
          email: 'rejected@example.test',
          csrfToken: 'INVALID',
        })
      ).status,
      403,
    );
    assert.deepEqual(
      db.prepare('SELECT display_name,email FROM users WHERE id=1').get(),
      attackedProfile.profile,
    );
    const legal = await send('/lab/profile-probe', {
      display_name: 'LEGAL',
      email: 'legal@example.test',
      csrfToken: i.csrfToken,
    });
    assert.equal(legal.status, 200);
    assert.equal((await legal.json()).persisted, true);
    assert.deepEqual(db.prepare('SELECT display_name,email FROM users WHERE id=1').get(), {
      display_name: 'LEGAL',
      email: 'legal@example.test',
    });
    const restored = await send('/lab/profile-restore', { csrfToken: i.csrfToken });
    assert.equal(restored.status, 200);
    assert.equal((await restored.json()).restored, true);
    assert.deepEqual(db.prepare('SELECT display_name,email FROM users WHERE id=1').get(), baseline);
    assert.equal((await send('/lab/profile-restore', { csrfToken: i.csrfToken })).status, 409);
    assert.equal(
      (
        await send('/tickets/new', {
          title: 'Legalne zgłoszenie',
          description: 'Opis',
          csrfToken: i.csrfToken,
        })
      ).status,
      302,
    );
    assert.match(await (await send('/tickets?saved=1')).text(), /Zgłoszenie zapisane/);
    assert.equal(
      (await send('/profile/update', { ...baseline, csrfToken: i.csrfToken })).status,
      302,
    );
    assert.match(await (await send('/profile?saved=1')).text(), /Dane profilu zostały zapisane/);
  } finally {
    await new Promise((r) => server.close(r));
    db.close();
  }
});
