require('dotenv').config();

const path = require('node:path');
const fs = require('node:fs');
const https = require('node:https');
const express = require('express');
const ejs = require('ejs');
const session = require('express-session');
const helmet = require('helmet');

const db = require('./src/database/db');
const { SessionStore, SESSION_DURATION } = require('./src/database/session-store');
const auth = require('./src/middleware/auth');
const { token, verify } = require('./src/security/csrf');
const { escapeHtml } = require('./src/security/render');
const xssDemo = require('./src/security/lab-xss');
const { testCards } = require('./src/security/scenario-cards');
const { instructionCommands } = require('./src/security/instructions');
const { generateProfile } = require('./src/security/lab-profile');

const app = express();
app.set('views', path.join(__dirname, 'src/views'));
app.set('view engine', 'html');
app.engine('html', (file, options, callback) => {
  ejs.renderFile(file, options, { escape: escapeHtml }, callback);
});

const port = process.env.PORT || 3000;
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
  configureSessionCookie(req);
  next();
});

function configureSessionCookie(req) {
  const secure = currentMode === 'secure';
  req.session.cookie.httpOnly = true;
  req.session.cookie.sameSite = secure ? 'strict' : 'lax';
  req.session.cookie.secure = secure && req.secure;
}

const renderDescription = (value) => (currentMode === 'secure' ? escapeHtml(value) : value);

function renderPage(res, page, title, data = {}) {
  res.render('layout', {
    page,
    title,
    mode: currentMode,
    secure: currentMode === 'secure',
    csrfToken: null,
    scriptPaths: [],
    ...data,
  });
}

app.get('/', (req, res) => res.redirect(req.session.userId ? '/security-tests' : '/login'));
app.get('/login', (req, res) => {
  if (req.session.userId) return res.redirect('/security-tests');
  renderPage(res, 'login', 'Logowanie');
});
app.post('/login', (req, res, next) => {
  const user = db
    .prepare('SELECT * FROM users WHERE username=? AND password=?')
    .get(req.body.username, req.body.password);
  if (!user) {
    return renderPage(res.status(401), 'login-error', 'Błąd');
  }

  req.session.regenerate((error) => {
    if (error) return next(error);
    req.session.userId = user.id;
    configureSessionCookie(req);
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
  const origin = req.get('origin');
  const applicationOrigin = `${req.protocol}://${req.get('host')}`;
  if (!req.is('application/json') || (origin && origin !== applicationOrigin)) {
    return res.status(403).json({ error: 'Zmiana trybu wymaga żądania JSON z aplikacji.' });
  }

  const requestedMode = String(req.body.mode || '').toLowerCase();
  if (!['vulnerable', 'secure'].includes(requestedMode)) {
    return res.status(400).json({ ok: false, error: 'invalid mode' });
  }

  currentMode = requestedMode;
  app.locals.isSecure = currentMode === 'secure';
  req.session.csrfToken = null;
  configureSessionCookie(req);
  res.json({ ok: true, mode: currentMode, reload: true });
});

app.get('/tickets', auth, (req, res) => {
  const tickets = db
    .prepare(
      `SELECT tickets.*, users.display_name
       FROM tickets
       JOIN users ON users.id = tickets.user_id
       ORDER BY tickets.id DESC`,
    )
    .all()
    .map((ticket) => ({
      ...ticket,
      description: renderDescription(ticket.description),
    }));

  renderPage(res, 'tickets', 'Zgłoszenia', { tickets, saved: !!req.query.saved });
});
app.get('/tickets/new', auth, (req, res) => {
  renderPage(res, 'ticket-new', 'Nowe zgłoszenie', {
    csrfToken: currentMode === 'secure' ? token(req) : null,
  });
});
app.post('/tickets/new', auth, verify, (req, res) => {
  if (!String(req.body.title || '').trim() || !String(req.body.description || '').trim()) {
    return res.status(400).send('Uzupełnij tytuł i opis.');
  }

  db.prepare('INSERT INTO tickets(user_id,title,description) VALUES(?,?,?)').run(
    req.session.userId,
    req.body.title,
    req.body.description,
  );
  res.redirect('/tickets?saved=1');
});
app.get('/profile', auth, (req, res) => {
  const state = profileState(req);

  renderPage(res, 'profile', 'Profil', {
    state,
    user: state.profile,
    saved: !!req.query.saved,
    csrfToken: currentMode === 'secure' ? token(req) : null,
    scriptPaths: ['/profile-demo.js'],
  });
});
app.post('/profile/update', auth, verify, (req, res) => {
  db.prepare('UPDATE users SET display_name=?,email=? WHERE id=?').run(
    req.body.display_name,
    req.body.email,
    req.session.userId,
  );
  res.redirect('/profile?saved=1');
});

app.get('/security-tests', auth, (req, res) => {
  token(req);
  const state = profileState(req);

  renderPage(res, 'security-tests', 'Security Tests', {
    state,
    cards: testCards(currentMode, state.profile),
    scriptPaths: ['/profile-demo.js', '/security-tests.js'],
  });
});

app.get('/instructions', auth, (req, res) => {
  renderPage(res, 'instructions', 'Instrukcja', { commands: instructionCommands() });
});
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
  if (description !== xssDemo.payload) {
    return res.status(400).json({
      error:
        'Ten scenariusz używa dokładnie payloadu zwróconego przez GET /lab/xss-info. Własny opis można sprawdzić w formularzu zgłoszenia.',
    });
  }

  db.prepare(
    `INSERT INTO lab_payloads(user_id, description) VALUES(?, ?)
       ON CONFLICT(user_id) DO UPDATE SET description = excluded.description`,
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
  if (!baseline && !record) {
    return res.status(404).send('Najpierw zapisz payload testowy: POST /lab/xss-probe.');
  }

  res.render('pages/xss-frame', {
    baseline,
    demo: xssDemo.baseline,
    description: baseline ? 'Opis bez payloadu.' : renderDescription(record.description),
  });
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
  ) {
    return res.status(400).json({ error: 'Podaj display_name i email.' });
  }

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
    const { profile: observed, initialProfile } = profileState(req);
    return {
      accepted: true,
      before,
      observed,
      changed: before.display_name !== observed.display_name || before.email !== observed.email,
      persisted: true,
      autoRestored: false,
      initialProfile,
    };
  })();
  res.json(result);
});
app.post('/lab/profile-restore', auth, (req, res) => {
  // To osobna legalna operacja, z poprawnym tokenem w OBU trybach.
  if (!req.body.csrfToken || req.body.csrfToken !== token(req)) {
    return res.status(403).send('403 Forbidden - invalid CSRF token');
  }

  const state = profileState(req);
  if (!state.initialProfile) {
    return res
      .status(409)
      .json({ error: 'Brak profilu początkowego. Nie wykonano jeszcze zaakceptowanej próby.' });
  }

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
  app.listen(port, host, () => console.log(`Hospital Service Desk: http://localhost:${port}`));
  if (process.env.TLS_KEY && process.env.TLS_CERT) {
    const httpsPort = process.env.HTTPS_PORT || 3443;
    https
      .createServer(
        { key: fs.readFileSync(process.env.TLS_KEY), cert: fs.readFileSync(process.env.TLS_CERT) },
        app,
      )
      .listen(httpsPort, host, () => console.log(`HTTPS: https://localhost:${httpsPort}`));
  }
}
module.exports = app;
