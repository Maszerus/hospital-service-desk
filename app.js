require('dotenv').config();
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const db = require('./src/database/db');
const { SessionStore, SESSION_DURATION } = require('./src/database/session-store');
const auth = require('./src/middleware/auth');
const { token, verify } = require('./src/security/csrf');
const { escapeHtml } = require('./src/security/render');
const xssDemo = require('./src/security/lab-xss');
const { testGuide } = require('./src/security/scenario-guide');
const path = require('path');
const { instructions } = require('./src/security/instructions');
const { generateProfile } = require('./src/security/lab-profile');

const app = express();
const PORT = process.env.PORT || 3000;
let currentMode =
  (process.env.APP_MODE || 'vulnerable').toLowerCase() === 'secure' ? 'secure' : 'vulnerable';
app.locals.getMode = () => currentMode;
app.locals.isSecure = currentMode === 'secure';

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

const secureHelmet = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      frameSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      upgradeInsecureRequests: null,
    },
  },
});
app.use((req, res, next) => (currentMode === 'secure' ? secureHelmet(req, res, next) : next()));
app.use(express.static('public'));
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'local-lab-secret',
    store: new SessionStore(db),
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: { httpOnly: true, sameSite: 'lax', secure: false, maxAge: SESSION_DURATION },
  }),
);
app.use((req, res, next) => {
  app.locals.isSecure = currentMode === 'secure';
  if (req.session) {
    req.session.cookie.httpOnly = true;
    req.session.cookie.sameSite = currentMode === 'secure' ? 'strict' : 'lax';
    req.session.cookie.secure = currentMode === 'secure' && req.secure;
  }
  next();
});

const modePanel = () =>
  `<section class="mode-panel">
<div>
<span>ŚRODOWISKO LABORATORYJNE · P7</span>
<strong class="mode-big ${currentMode}">${currentMode === 'secure' ? 'Ochrona włączona' : 'Wersja podatna'}</strong>
<small>${currentMode === 'secure' ? 'Powtórz ataki i sprawdź, czy zabezpieczenia je zatrzymują.' : 'Uruchom kontrolowane ataki i zobacz ich skutki.'}</small>
</div>
<div class="mode-switch">
<button type="button" data-mode="vulnerable" class="${currentMode === 'vulnerable' ? 'active' : ''}">1. Przed ochroną</button>
<button type="button" data-mode="secure" class="${currentMode === 'secure' ? 'active' : ''}">2. Po zabezpieczeniu</button>
</div>
</section>`;
const labDashboard = () =>
  `<div class="lab-grid">
<div>
<span>Kodowanie HTML</span>
<b>${currentMode === 'secure' ? 'Aktywne' : 'Wyłączone'}</b>
</div>
<div>
<span>Token CSRF</span>
<b>${currentMode === 'secure' ? 'Sprawdzany' : 'Niesprawdzany'}</b>
</div>
<div>
<span>Polityka CSP</span>
<b>${currentMode === 'secure' ? 'Aktywna' : 'Wyłączona'}</b>
</div>
<div>
<span>Cookie sesji</span>
<b>HttpOnly · ${currentMode === 'secure' ? 'Strict' : 'Lax'}</b>
</div>
</div>`;
const nav = () =>
  `<nav aria-label="Nawigacja główna">
<a href="/security-tests">Laboratorium bezpieczeństwa</a>
<a href="/tickets">Zgłoszenia</a>
<a href="/profile">Profil testowy</a>
<a href="/instructions">Instrukcja i Postman</a>
<form method="post" action="/logout">
<button class="quiet">Wyloguj</button>
</form>
</nav>`;
const layout = (title, body, script = '') => {
  const active =
    title === 'Security Tests'
      ? '/security-tests'
      : title === 'Instrukcja'
        ? '/instructions'
        : title === 'Profil'
          ? '/profile'
          : title === 'Zgłoszenia' || title === 'Nowe zgłoszenie'
            ? '/tickets'
            : null;
  if (active) body = body.replace(`href="${active}"`, `href="${active}" aria-current="page"`);
  return `<!doctype html>
<html lang="pl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} · Hospital Service Desk</title>
<link rel="stylesheet" href="/style.css">
</head>
<body data-lab-mode="${currentMode}">
<header id="app-header">
<a href="/security-tests" id="app-brand">
<span class="brand-mark">H+</span> Hospital Service Desk</a>
<button type="button" class="mode ${currentMode}" data-mode="${currentMode === 'secure' ? 'vulnerable' : 'secure'}" aria-label="${currentMode === 'secure' ? 'Wyłącz ochronę' : 'Włącz ochronę'}" title="${currentMode === 'secure' ? 'Kliknij, aby wyłączyć ochronę' : 'Kliknij, aby włączyć ochronę'}">${currentMode === 'secure' ? 'Ochrona aktywna' : 'Wersja podatna'}</button>
</header>
<aside id="xss-page-impact" class="page-impact" role="status" hidden>
</aside>
<main>${body}</main><script src="/remember-login.js"></script><script src="/mode-switch.js"></script>${script}</body>
</html>`;
};
const renderDescription = (value) => (currentMode === 'secure' ? escapeHtml(value) : value);
const notice = (text) => `<div class="notice" role="status">✓ ${text}</div>`;

app.get('/', (req, res) => res.redirect(req.session.userId ? '/security-tests' : '/login'));
app.get('/login', (req, res) => {
  if (req.session.userId) return res.redirect('/security-tests');
  res.send(
    layout(
      'Logowanie',
      `<div class="eyebrow">P7 · BROWSER HARDENING</div>
<h1>Wejdź do laboratorium</h1>
<p>Przetestuj XSS i CSRF, włącz ochronę i porównaj efekty.</p>
<form method="post">
<label>Login<input name="username" autocomplete="username" required>
</label>
<label>Hasło<input type="password" name="password" autocomplete="current-password" required>
</label>
<button>Zaloguj</button>
</form>
<p class="hint">LAB: student / student123</p>`,
    ),
  );
});
app.post('/login', (req, res, next) => {
  const u = db
    .prepare('SELECT * FROM users WHERE username=? AND password=?')
    .get(req.body.username, req.body.password);
  if (!u)
    return res.status(401).send(layout('Błąd', '<h1>Błędne dane</h1><a href="/login">Wróć</a>'));
  req.session.regenerate((error) => {
    if (error) return next(error);
    req.session.userId = u.id;
    req.session.cookie.sameSite = currentMode === 'secure' ? 'strict' : 'lax';
    req.session.cookie.secure = currentMode === 'secure' && req.secure;
    req.session.save((saveError) => {
      if (saveError) return next(saveError);
      res.redirect('/security-tests');
    });
  });
});
app.post('/logout', (req, res, next) => {
  req.session.destroy((error) => {
    if (error) return next(error);
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});
app.post('/lab/mode', auth, (req, res) => {
  if (
    !req.is('application/json') ||
    (req.get('origin') && req.get('origin') !== req.protocol + '://' + req.get('host'))
  )
    return res.status(403).json({ error: 'Zmiana trybu wymaga żądania JSON z aplikacji.' });
  const requested = String(req.body.mode || '').toLowerCase();
  if (!['vulnerable', 'secure'].includes(requested))
    return res.status(400).json({ ok: false, error: 'invalid mode' });
  currentMode = requested;
  app.locals.isSecure = currentMode === 'secure';
  req.session.csrfToken = null;
  req.session.cookie.sameSite = currentMode === 'secure' ? 'strict' : 'lax';
  res.json({ ok: true, mode: currentMode, reload: true });
});

app.get('/tickets', auth, (req, res) => {
  const rows = db
    .prepare(
      'SELECT tickets.*,users.display_name FROM tickets JOIN users ON users.id=tickets.user_id ORDER BY tickets.id DESC',
    )
    .all();
  const items = rows
    .map(
      (t) =>
        `<article class="ticket"><span class="ticket-number">Zgłoszenie #${t.id}</span><h3>${escapeHtml(t.title)}</h3><small>${escapeHtml(t.display_name)}</small><div class="desc">${renderDescription(t.description)}</div></article>`,
    )
    .join('');
  res.send(
    layout(
      'Zgłoszenia',
      `${nav()}${modePanel()}${labDashboard()}<h1>Zgłoszenia serwisowe</h1>
<p>Dodaj zgłoszenie i od razu zobacz zapisany opis. W laboratorium ten opis jest kontrolowaną ścieżką Stored XSS.</p>${req.query.saved ? notice('Zgłoszenie zapisane. Znajdziesz je na początku listy.') : ''}<p>
<a class="primary-link" href="/tickets/new">+ Nowe zgłoszenie</a>
</p>${items}`,
    ),
  );
});
app.get('/tickets/new', auth, (req, res) =>
  res.send(
    layout(
      'Nowe zgłoszenie',
      `${nav()}<h1>Nowe zgłoszenie</h1><div class="lab-help"><b>Scenariusz Stored XSS</b><p>Ręczny payload LAB: <code>&lt;script src=&quot;/xss-demo.js&quot;&gt;&lt;/script&gt;</code></p></div><form method="post">${currentMode === 'secure' ? `<input type="hidden" name="csrfToken" value="${token(req)}">` : ''}<label>Tytuł<input name="title" required></label><label>Opis<textarea name="description" required></textarea></label><button>Zapisz</button></form>`,
    ),
  ),
);
app.post('/tickets/new', auth, verify, (req, res) => {
  if (!String(req.body.title || '').trim() || !String(req.body.description || '').trim())
    return res.status(400).send('Uzupełnij tytuł i opis.');
  db.prepare('INSERT INTO tickets(user_id,title,description) VALUES(?,?,?)').run(
    req.session.userId,
    req.body.title,
    req.body.description,
  );
  res.redirect('/tickets?saved=1');
});
app.get('/profile', auth, (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.session.userId);
  const csrf =
    currentMode === 'secure' ? `<input type="hidden" name="csrfToken" value="${token(req)}">` : '';
  res.send(
    layout(
      'Profil',
      `${nav()}${modePanel()}${labDashboard()}${profilePanel(req)}<h1>Profil testowy</h1>
<p>Zmiana tych danych pokazuje skutek żądania CSRF. Zapis formularza to legalna operacja użytkownika.</p>${req.query.saved ? notice('Dane profilu zostały zapisane.') : ''}<form method="post" action="/profile/update">${csrf}<label>Nazwa<input name="display_name" value="${escapeHtml(u.display_name)}">
</label>
<label>E-mail<input name="email" value="${escapeHtml(u.email)}">
</label>
<button>Zapisz</button>
</form>`,
      `<script src="/profile-demo.js"></script>`,
    ),
  );
});
app.post('/profile/update', auth, verify, (req, res) => {
  db.prepare('UPDATE users SET display_name=?,email=? WHERE id=?').run(
    req.body.display_name,
    req.body.email,
    req.session.userId,
  );
  res.redirect('/profile?saved=1');
});

const testsForMode = () =>
  currentMode === 'vulnerable'
    ? [
        [
          'T1',
          'Stored XSS — atak',
          'Czy kontrolowany payload zostanie wykonany jako JavaScript?',
          'WYKONAJ ATAK XSS',
        ],
        [
          'T3',
          'CSRF bez tokenu — atak',
          'Czy żądanie zmieniające stan zostanie zaakceptowane bez tokenu?',
          'WYKONAJ CSRF',
        ],
        [
          'T4',
          'CSRF z błędnym tokenem — atak',
          'Czy błędny token mimo wszystko pozwoli zmienić stan?',
          'WYŚLIJ BŁĘDNY TOKEN',
        ],
        [
          'T6',
          'Security headers + cookies — baseline',
          'Jak wygląda rzeczywista konfiguracja nagłówków i sesji w trybie podatnym?',
          'SPRAWDŹ HARDENING',
        ],
      ]
    : [
        [
          'T2',
          'Stored XSS — RE-TEST',
          'Czy ten sam payload po remediacji pozostanie danymi?',
          'POWTÓRZ ATAK XSS',
        ],
        [
          'T3',
          'CSRF bez tokenu — RE-TEST',
          'Czy żądanie bez tokenu zostanie odrzucone?',
          'POWTÓRZ CSRF',
        ],
        [
          'T4',
          'CSRF z błędnym tokenem — RE-TEST',
          'Czy niepoprawny token zostanie odrzucony?',
          'WYŚLIJ BŁĘDNY TOKEN',
        ],
        [
          'T5',
          'CSRF z poprawnym tokenem',
          'Czy legalne żądanie z poprawnym tokenem nadal działa?',
          'WYŚLIJ POPRAWNY TOKEN',
        ],
        [
          'T6',
          'CSP + nagłówki + cookies — RE-TEST',
          'Czy mechanizmy hardeningu są rzeczywiście aktywne?',
          'SPRAWDŹ HARDENING',
        ],
      ];
app.get('/security-tests', auth, (req, res) => {
  token(req);
  const profile = db.prepare('SELECT display_name FROM users WHERE id=?').get(req.session.userId);
  const cards = testsForMode()
    .map(([id, name, description, button]) => {
      const action = ['T1', 'T2', 'T3', 'T4'].includes(id) ? 'Wykonaj atak' : button;

      return `
        <section class="test-card" id="card-${id}">
          <div class="test-head">
            <div>
              <span class="test-id">${id}</span>
              <h2>${name}</h2>
            </div>
            <button type="button" class="run-test" data-test="${id}">${action}</button>
          </div>
          <details class="test-details">
            <summary>Szczegóły testu / ataku</summary>
            <p>${description}</p>
            ${testGuide(id, currentMode, generateProfile(profile))}
          </details>
          <div class="test-result" aria-live="polite" id="result-${id}"></div>
        </section>
      `;
    })
    .join('');

  res.send(
    layout(
      'Security Tests',
      `${nav()}${modePanel()}${labDashboard()}
        <div class="test-center-title">
          <h1>Testy bezpieczeństwa</h1>
          <div id="xss-reset-area" hidden>
            <button type="button" id="reset-xss" class="secondary">Przywróć nagłówek aplikacji</button>
          </div>
        </div>
        <div class="test-actions">
          <button type="button" id="run-all">Uruchom wszystkie testy</button>
          <p id="all-summary" aria-live="polite"></p>
        </div>
        ${cards}
        <details class="lab-details">
          <summary>Profil testowy</summary>
          ${profilePanel(req)}
          <p class="muted">Zaakceptowany test CSRF zapisuje nowe dane w profilu. Przywrócenie danych wymaga osobnego kliknięcia.</p>
        </details>
        <details class="lab-details" id="comparison-panel">
          <summary>Porównanie wyników i raport</summary>
          <div class="comparison-head">
            <h2>Przed i po zabezpieczeniu</h2>
            <button type="button" id="export-report" class="secondary">Pobierz dowody JSON</button>
          </div>
          <div id="comparison-results"></div>
        </details>`,
      `<script src="/profile-demo.js"></script><script src="/security-tests.js"></script>`,
    ),
  );
});

app.get('/instructions', auth, (req, res) =>
  res.send(layout('Instrukcja', `${nav()}${instructions()}`)),
);
const labDownloads = {
  postman: 'postman/BAI-P7.postman_collection.json',
  'manual-restore': 'postman/BAI-P7-manual-restore.postman_collection.json',
  'http-env': 'postman/localhost.postman_environment.json',
  'https-env': 'postman/localhost-https.postman_environment.json',
  manual: 'docs/postman.md',
  curl: 'scripts/demo-curl.sh',
};
app.get('/lab/download/:kind', auth, (req, res) => {
  const file = Object.hasOwn(labDownloads, req.params.kind) ? labDownloads[req.params.kind] : null;
  if (!file) return res.status(404).send('Nieznany materiał.');
  res.download(path.join(__dirname, file));
});

app.get('/lab/xss-info', auth, (req, res) => {
  const record = db
    .prepare('SELECT user_id,description FROM lab_payloads WHERE user_id=?')
    .get(req.session.userId);
  res.json({
    mode: currentMode,
    payload: xssDemo.payload,
    script: xssDemo.script,
    baseline: xssDemo.baseline,
    changes: xssDemo.changes,
    storage: { table: 'lab_payloads', userId: req.session.userId, record: record || null },
    trigger:
      'Brak obrazu /lab/missing-image wywołuje onerror; niezaufany opis staje się kodem HTML.',
    activeRenderer: currentMode === 'secure' ? 'escapeHtml(description)' : 'description',
    frameUrl: '/lab/xss-frame',
    baselineUrl: '/lab/xss-frame?baseline=1',
  });
});
app.post('/lab/xss-probe', auth, (req, res) => {
  const description = req.body?.description ?? xssDemo.payload;
  if (description !== xssDemo.payload)
    return res.status(400).json({
      error:
        'Ten scenariusz używa dokładnie payloadu zwróconego przez GET /lab/xss-info. Własny opis można sprawdzić w formularzu zgłoszenia.',
    });
  db.prepare(
    'INSERT INTO lab_payloads(user_id,description) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET description=excluded.description',
  ).run(req.session.userId, description);
  const record = db
    .prepare('SELECT user_id,description FROM lab_payloads WHERE user_id=?')
    .get(req.session.userId);
  res.json({
    stored: true,
    payload: record.description,
    storage: { table: 'lab_payloads', record },
    frameUrl: '/lab/xss-frame',
  });
});
app.get('/lab/xss-frame', auth, (req, res) => {
  const baseline = req.query.baseline === '1';
  const record = baseline
    ? null
    : db.prepare('SELECT description FROM lab_payloads WHERE user_id=?').get(req.session.userId);
  if (!baseline && !record)
    return res.status(404).send('Najpierw zapisz payload testowy: POST /lab/xss-probe.');
  res.type('html').send(
    `<!doctype html>
<html lang="pl">
<head>
<meta charset="utf-8">
<link rel="stylesheet" href="/style.css">
</head>
<body class="demo-document">
<span class="eyebrow">${baseline ? 'STRONA PRZED WSTAWIENIEM OPISU' : 'STRONA PO ODCZYTANIU OPISU Z SQLITE'}</span>
<h2 id="effect">${xssDemo.baseline.title}</h2>
<div class="demo-fields">
<div>
<span>Priorytet</span>
<b id="demo-priority">${xssDemo.baseline.priority}</b>
</div>
<div>
<span>Opiekun</span>
<b id="demo-owner">${xssDemo.baseline.owner}</b>
</div>
</div>
<button type="button" disabled id="demo-action">${xssDemo.baseline.action}</button>
<p class="demo-note">To kontrolowany widok demonstracyjny. Priorytet i opiekun nie są danymi zgłoszenia w bazie. XSS zmienia DOM, a nie rekord SQL.</p>
<div id="payload">${baseline ? 'Opis bez payloadu.' : renderDescription(record.description)}</div>
</body>
</html>`,
  );
});
function profileState(req) {
  const profile = db
    .prepare('SELECT display_name,email FROM users WHERE id=?')
    .get(req.session.userId);
  const initialProfile =
    db
      .prepare('SELECT display_name,email FROM lab_profile_baselines WHERE user_id=?')
      .get(req.session.userId) || null;
  return { mode: currentMode, profile, initialProfile, canRestore: !!initialProfile };
}
function profilePanel(req) {
  const state = profileState(req);
  return `<section class="live-profile" aria-label="Aktualny profil w bazie">
<div>
<span class="eyebrow">AKTUALNY PROFIL · ODCZYT Z SQLITE</span>
<strong id="live-profile-name">${escapeHtml(state.profile.display_name)}</strong>
<span id="live-profile-email">${escapeHtml(state.profile.email)}</span>
<small id="live-profile-baseline">${state.initialProfile ? `Profil sprzed pierwszej próby: ${escapeHtml(state.initialProfile.display_name)} · ${escapeHtml(state.initialProfile.email)}` : 'Nie zachowano jeszcze profilu początkowego.'}</small>
<p id="profile-change-note">${state.canRestore ? 'Zapis po demonstracji pozostaje w bazie. Przywrócenie danych jest osobną operacją.' : 'Po zaakceptowanym teście zobaczysz tutaj nowe dane. Nic nie zostanie automatycznie cofnięte.'}</p>
</div>
<div>
<button type="button" class="secondary" id="restore-profile" ${state.canRestore ? '' : 'disabled'}>Przywróć profil sprzed pierwszej próby</button>
<a href="/profile">Otwórz profil testowy →</a>
<p id="profile-action-status" role="status">
</p>
</div>
</section>`;
}
app.get('/lab/profile-state', auth, (req, res) => res.json(profileState(req)));
app.get('/lab/profile-candidate', auth, (req, res) =>
  res.json(generateProfile(profileState(req).profile)),
);
app.post('/lab/profile-probe', auth, verify, (req, res) => {
  if (
    typeof req.body.display_name !== 'string' ||
    !req.body.display_name.trim() ||
    typeof req.body.email !== 'string' ||
    !req.body.email.trim()
  )
    return res.status(400).json({ error: 'Podaj display_name i email.' });
  const result = db.transaction(() => {
    const before = profileState(req).profile;
    db.prepare(
      'INSERT OR IGNORE INTO lab_profile_baselines(user_id,display_name,email) VALUES(?,?,?)',
    ).run(req.session.userId, before.display_name, before.email);
    db.prepare('UPDATE users SET display_name=?,email=? WHERE id=?').run(
      req.body.display_name,
      req.body.email,
      req.session.userId,
    );
    const observed = profileState(req).profile;
    return {
      accepted: true,
      before,
      observed,
      changed: before.display_name !== observed.display_name || before.email !== observed.email,
      persisted: true,
      autoRestored: false,
      initialProfile: profileState(req).initialProfile,
    };
  })();
  res.json(result);
});
app.post('/lab/profile-restore', auth, (req, res) => {
  // To osobna legalna operacja, z poprawnym tokenem w OBU trybach.
  if (!req.body.csrfToken || req.body.csrfToken !== token(req))
    return res.status(403).send('403 Forbidden - invalid CSRF token');
  const state = profileState(req);
  if (!state.initialProfile)
    return res
      .status(409)
      .json({ error: 'Brak profilu początkowego. Nie wykonano jeszcze zaakceptowanej próby.' });
  const result = db.transaction(() => {
    db.prepare('UPDATE users SET display_name=?,email=? WHERE id=?').run(
      state.initialProfile.display_name,
      state.initialProfile.email,
      req.session.userId,
    );
    db.prepare('DELETE FROM lab_profile_baselines WHERE user_id=?').run(req.session.userId);
    const restoredState = profileState(req).profile;
    return {
      restored: JSON.stringify(restoredState) === JSON.stringify(state.initialProfile),
      before: state.profile,
      restoredState,
      manual: true,
    };
  })();
  res.json(result);
});
app.get('/lab/test-info', auth, (req, res) => {
  const secure = currentMode === 'secure';
  res.json({
    mode: currentMode,
    isSecure: secure,
    csrfToken: token(req),
    headers: {
      csp: res.getHeader('Content-Security-Policy') || null,
      xContentType: res.getHeader('X-Content-Type-Options') || null,
      xFrame: res.getHeader('X-Frame-Options') || null,
    },
    cookie: {
      httpOnly: req.session.cookie.httpOnly,
      sameSite: req.session.cookie.sameSite,
      secure: req.session.cookie.secure,
    },
    code: {
      xssActive: secure ? 'escapeHtml(t.description)' : 't.description',
      xssVulnerable: 'const rendered = ticket.description; // bez output encoding',
      xssSecure: 'const rendered = escapeHtml(ticket.description); // output encoding',
      csrfActive: secure
        ? 'verify(req,res,next) aktywne'
        : 'verify() przepuszcza żądanie w trybie vulnerable',
      csrfVerify: 'if (isSecure && (!csrfToken || csrfToken !== sessionToken)) return 403;',
      helmet: "if (mode === 'secure') helmet({ contentSecurityPolicy: ... })(req,res,next);",
      cookie:
        "session.cookie.sameSite = mode === 'secure' ? 'strict' : 'lax';\nsession.cookie.httpOnly = true;",
    },
  });
});
app.get('/health', (req, res) => res.json({ status: 'ok', mode: currentMode }));
if (require.main === module) {
  const host = '127.0.0.1';
  app.listen(PORT, host, () => console.log(`Hospital Service Desk: http://localhost:${PORT}`));
  if (process.env.TLS_KEY && process.env.TLS_CERT) {
    const fs = require('fs');
    require('https')
      .createServer(
        { key: fs.readFileSync(process.env.TLS_KEY), cert: fs.readFileSync(process.env.TLS_CERT) },
        app,
      )
      .listen(process.env.HTTPS_PORT || 3443, host, () =>
        console.log('HTTPS: https://localhost:' + (process.env.HTTPS_PORT || 3443)),
      );
  }
}
module.exports = app;
