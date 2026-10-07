const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
process.env.DB_PATH = ':memory:';
process.env.APP_MODE = 'vulnerable';
const app = require('../app');
const db = require('../src/database/db');
(async () => {
  const server = app.listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const attacker = http
    .createServer((req, res) => {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(
        `<form action="${base}/profile/update" method="POST"><input name="display_name" value="CSRF z innego origin"><input name="email" value="csrf@example.test"><button>Atak</button></form>`,
      );
    })
    .listen(0, '127.0.0.1');
  await new Promise((r) => attacker.once('listening', r));
  let tlsServer, browser;
  try {
    const chrome = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
    browser = await chromium.launch(
      fs.existsSync(chrome) ? { executablePath: chrome, headless: true } : { headless: true },
    );
    const context = await browser.newContext({ viewport: { width: 1440, height: 1050 } });
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', (e) => errors.push(e.message));
    await page.goto(base + '/login');
    await page.locator('[name=username]').fill('student');
    await page.locator('[name=password]').fill('student123');
    await page.getByRole('button', { name: 'Zaloguj' }).click();
    await page.waitForURL('**/security-tests');
    const attackDetails = page.locator('#card-T1 .test-details');
    assert.equal(await attackDetails.evaluate((element) => element.open), false);
    assert.equal(await page.locator('#card-T1 .scenario-guide').isVisible(), false);
    await attackDetails.locator('summary').click();
    assert.equal(await page.locator('#card-T1 .scenario-guide').isVisible(), true);
    await attackDetails.locator('summary').click();
    assert.equal(await page.locator('#card-T1 .scenario-guide').isVisible(), false);
    assert.equal(await page.locator('#result-T1').isVisible(), false);
    const original = db.prepare('SELECT display_name,email FROM users WHERE id=1').get();
    await page.locator('#run-all').click();
    await page.waitForFunction(() =>
      document.querySelector('#all-summary').textContent.startsWith('4/4'),
    );
    assert.match(
      await page.frameLocator('[data-frame=after]').locator('#effect').textContent(),
      /ATAK XSS/,
    );
    assert.equal(
      await page.locator('#app-header').evaluate((el) => el.classList.contains('xss-header')),
      true,
    );
    assert.equal(await page.locator('#xss-page-impact').isVisible(), true);
    assert.match(
      await page.frameLocator('[data-frame=after]').locator('#demo-priority').textContent(),
      /KRYTYCZNY/,
    );
    assert.equal(await page.locator('#result-T1 .changed-row').count(), 7);
    await page.screenshot({ path: 'evidence/before-dashboard.png', fullPage: true });
    await page
      .locator('#result-T1 .paired-preview')
      .screenshot({ path: 'evidence/xss-visible-changes.png' });
    await attackDetails.locator('summary').click();
    await page.locator('#card-T1 .scenario-guide').screenshot({
      path: 'evidence/xss-exact-payload.png',
      style: '#app-header,.page-impact,.scenario-index{visibility:hidden!important}',
    });
    await attackDetails.locator('summary').click();
    await page.locator('#result-T3 .outcome').screenshot({
      path: 'evidence/csrf-persistent-change.png',
      style: '#app-header,.page-impact,.scenario-index{visibility:hidden!important}',
    });
    const baseline = db.prepare('SELECT display_name,email FROM users WHERE id=1').get();
    assert.notDeepEqual(baseline, original);
    assert.equal(await page.locator('#live-profile-name').textContent(), baseline.display_name);
    const savedProfilePage = await context.newPage();
    await savedProfilePage.goto(base + '/profile');
    assert.equal(
      await savedProfilePage.locator('[name=display_name]').inputValue(),
      baseline.display_name,
    );
    await savedProfilePage.reload();
    assert.equal(await savedProfilePage.locator('[name=email]').inputValue(), baseline.email);
    await savedProfilePage.close();
    const priorCandidate = await page.evaluate(
      () => JSON.parse(sessionStorage.getItem('hsd-evidence')).vulnerable.T3.candidate,
    );
    await page.locator('[data-test=T3]').click();
    await page.waitForFunction(() => !document.querySelector('[data-test=T3]').disabled);
    const nextCandidate = await page.evaluate(
      () => JSON.parse(sessionStorage.getItem('hsd-evidence')).vulnerable.T3.candidate,
    );
    assert.notEqual(baseline.display_name, nextCandidate.display_name);
    assert.notEqual(priorCandidate.email, nextCandidate.email);
    const other = await context.newPage();
    await other.goto(`http://127.0.0.1:${attacker.address().port}`);
    await other.getByRole('button').click();
    await other.waitForURL('**/profile?saved=1');
    assert.equal(
      db.prepare('SELECT display_name FROM users WHERE id=1').get().display_name,
      'CSRF z innego origin',
    );
    db.prepare('UPDATE users SET display_name=?,email=? WHERE id=1').run(
      baseline.display_name,
      baseline.email,
    );
    await page.locator('[data-mode=secure]').click();
    await page.waitForLoadState('networkidle');
    await page.locator('#run-all').click();
    await page.waitForFunction(() =>
      document.querySelector('#all-summary').textContent.startsWith('5/5'),
    );
    assert.equal(await page.frameLocator('[data-frame=after]').locator('#payload img').count(), 0);
    assert.equal(
      await page.locator('#app-header').evaluate((el) => el.classList.contains('xss-header')),
      false,
    );
    assert.equal(await page.locator('#xss-page-impact').isVisible(), false);
    assert.equal(await page.locator('#result-T2 .changed-row').count(), 0);
    await page.screenshot({ path: 'evidence/after-dashboard.png', fullPage: true });
    await page
      .locator('#result-T2 .paired-preview')
      .screenshot({ path: 'evidence/xss-blocked.png' });
    const secureProfile = db.prepare('SELECT display_name,email FROM users WHERE id=1').get();
    const evidence = await page.evaluate(() => JSON.parse(sessionStorage.getItem('hsd-evidence')));
    fs.writeFileSync(
      'evidence/browser-results.json',
      JSON.stringify(
        { scope: 'Automatyczny test localhost na osobnej bazie in-memory', results: evidence },
        null,
        2,
      ),
    );
    const downloadPromise = page.waitForEvent('download');
    await page.locator('#export-report').click();
    const download = await downloadPromise;
    await download.saveAs('evidence/P7-evidence-before-after.json');
    assert.ok(
      JSON.parse(fs.readFileSync('evidence/P7-evidence-before-after.json')).results.secure.XSS.pass,
    );
    await other.goto(`http://127.0.0.1:${attacker.address().port}`);
    const responsePromise = other.waitForResponse((r) => r.url().endsWith('/profile/update'));
    await other.getByRole('button').click();
    assert.equal((await responsePromise).status(), 403);
    assert.deepEqual(
      db.prepare('SELECT display_name,email FROM users WHERE id=1').get(),
      secureProfile,
    );
    fs.writeFileSync(
      'evidence/cross-origin-results.json',
      JSON.stringify(
        {
          scope: 'Dwa origin na 127.0.0.1; ten sam site, różne porty',
          before: { accepted: true, observedName: 'CSRF z innego origin' },
          after: { status: 403, profileUnchanged: true },
        },
        null,
        2,
      ),
    );
    await page
      .locator('.lab-details')
      .filter({ has: page.locator('#restore-profile') })
      .locator('summary')
      .click();
    await page.locator('#restore-profile').click();
    await page.waitForFunction(() =>
      document.querySelector('#profile-action-status').textContent.startsWith('Profil przywrócony'),
    );
    assert.deepEqual(db.prepare('SELECT display_name,email FROM users WHERE id=1').get(), original);
    assert.equal(await page.locator('#restore-profile').isDisabled(), true);
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(
      await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
      true,
    );
    await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'instant' }));
    await page.screenshot({ path: 'evidence/mobile.png' });
    await page
      .locator('#result-T2 .paired-preview')
      .screenshot({ path: 'evidence/mobile-xss.png' });
    assert.deepEqual(errors, []);
    const instructionsResponse = await context.request.get(base + '/instructions');
    assert.equal(instructionsResponse.status(), 200);
    assert.match(await instructionsResponse.text(), /Postman/);
    const downloadedCollection = await context.request.get(base + '/lab/download/postman');
    assert.equal(downloadedCollection.status(), 200);
    assert.ok((await downloadedCollection.json()).item.length > 0);
    const manualResponse = await context.request.get(base + '/lab/download/manual');
    assert.equal(manualResponse.status(), 200);
    assert.match(await manualResponse.text(), /T1\/T2/);
    if (fs.existsSync('.certs/localhost-key.pem')) {
      tlsServer = https
        .createServer(
          {
            key: fs.readFileSync('.certs/localhost-key.pem'),
            cert: fs.readFileSync('.certs/localhost-cert.pem'),
          },
          app,
        )
        .listen(0, '127.0.0.1');
      await new Promise((r) => tlsServer.once('listening', r));
      const tlsContext = await browser.newContext({ ignoreHTTPSErrors: true });
      const tlsPage = await tlsContext.newPage();
      await tlsPage.goto(`https://127.0.0.1:${tlsServer.address().port}/login`);
      await tlsPage.locator('[name=username]').fill('student');
      await tlsPage.locator('[name=password]').fill('student123');
      const loginResponse = tlsPage.waitForResponse(
        (r) => r.url().endsWith('/login') && r.request().method() === 'POST',
      );
      await tlsPage.getByRole('button', { name: 'Zaloguj' }).click();
      const setCookie = (await (await loginResponse).allHeaders())['set-cookie'];
      assert.match(setCookie, /Secure/);
      const cookie = (await tlsContext.cookies()).find((c) => c.name === 'connect.sid');
      assert.equal(cookie.secure, true);
      assert.equal(cookie.httpOnly, true);
      assert.equal(cookie.sameSite, 'Strict');
      await tlsPage.locator('[data-test=T6]').click();
      await tlsPage.waitForFunction(() =>
        document.querySelector('#result-T6').textContent.includes('Secure=true'),
      );
      fs.writeFileSync(
        'evidence/https-results.json',
        JSON.stringify(
          {
            scope: 'Lokalne HTTPS z certyfikatem testowym; tryb secure',
            setCookie: setCookie.replace(/connect.sid=[^;]+/, 'connect.sid=[REDACTED]'),
            browserCookie: {
              secure: cookie.secure,
              httpOnly: cookie.httpOnly,
              sameSite: cookie.sameSite,
            },
            test: 'T6',
            passed: true,
          },
          null,
          2,
        ),
      );
      console.log('HTTPS: Secure, HttpOnly i SameSite=Strict potwierdzone w przeglądarce');
    } else console.log('HTTPS pominięte: najpierw npm run https:cert');
    console.log(
      'BEFORE 4/4; AFTER 5/5; cross-origin CSRF: zmiana → 403; losowe dane i trwały zapis OK; ręczny restore OK; eksport JSON i mobile OK; 0 błędów JS',
    );
  } finally {
    if (browser) await browser.close();
    await new Promise((r) => server.close(r));
    await new Promise((r) => attacker.close(r));
    if (tlsServer) await new Promise((r) => tlsServer.close(r));
    db.close();
  }
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
