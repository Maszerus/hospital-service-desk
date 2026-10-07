const pageRoutes = {
  'Security Tests': '/security-tests',
  Instrukcja: '/instructions',
  Profil: '/profile',
  Zgłoszenia: '/tickets',
  'Nowe zgłoszenie': '/tickets',
};

function modePanel(mode) {
  const secure = mode === 'secure';
  const description = secure
    ? 'Powtórz ataki i sprawdź, czy zabezpieczenia je zatrzymują.'
    : 'Uruchom kontrolowane ataki i zobacz ich skutki.';

  return `
    <section class="mode-panel">
      <div>
        <span>ŚRODOWISKO LABORATORYJNE · P7</span>
        <strong class="mode-big ${mode}">${secure ? 'Ochrona włączona' : 'Wersja podatna'}</strong>
        <small>${description}</small>
      </div>
      <div class="mode-switch">
        <button type="button" data-mode="vulnerable" class="${secure ? '' : 'active'}">1. Przed ochroną</button>
        <button type="button" data-mode="secure" class="${secure ? 'active' : ''}">2. Po zabezpieczeniu</button>
      </div>
    </section>
  `;
}

function labDashboard(mode) {
  const secure = mode === 'secure';

  return `
    <div class="lab-grid">
      <div>
        <span>Kodowanie HTML</span>
        <b>${secure ? 'Aktywne' : 'Wyłączone'}</b>
      </div>
      <div>
        <span>Token CSRF</span>
        <b>${secure ? 'Sprawdzany' : 'Niesprawdzany'}</b>
      </div>
      <div>
        <span>Polityka CSP</span>
        <b>${secure ? 'Aktywna' : 'Wyłączona'}</b>
      </div>
      <div>
        <span>Cookie sesji</span>
        <b>HttpOnly · ${secure ? 'Strict' : 'Lax'}</b>
      </div>
    </div>
  `;
}

function nav() {
  return `
    <nav aria-label="Nawigacja główna">
      <a href="/security-tests">Laboratorium bezpieczeństwa</a>
      <a href="/tickets">Zgłoszenia</a>
      <a href="/profile">Profil testowy</a>
      <a href="/instructions">Instrukcja i Postman</a>
      <form method="post" action="/logout">
        <button class="quiet">Wyloguj</button>
      </form>
    </nav>
  `;
}

function layout(mode, title, body, script = '') {
  const activePath = pageRoutes[title];
  const secure = mode === 'secure';
  const nextMode = secure ? 'vulnerable' : 'secure';
  const modeAction = secure ? 'Wyłącz ochronę' : 'Włącz ochronę';
  const modeHint = secure ? 'Kliknij, aby wyłączyć ochronę' : 'Kliknij, aby włączyć ochronę';

  if (activePath) {
    body = body.replace(`href="${activePath}"`, `href="${activePath}" aria-current="page"`);
  }

  return `<!doctype html>
    <html lang="pl">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>${title} · Hospital Service Desk</title>
        <link rel="stylesheet" href="/style.css">
      </head>
      <body data-lab-mode="${mode}">
        <header id="app-header">
          <a href="/security-tests" id="app-brand"><span class="brand-mark">H+</span> Hospital Service Desk</a>
          <button type="button" class="mode ${mode}" data-mode="${nextMode}"
            aria-label="${modeAction}" title="${modeHint}">${secure ? 'Ochrona aktywna' : 'Wersja podatna'}</button>
        </header>
        <aside id="xss-page-impact" class="page-impact" role="status" hidden></aside>
        <main>${body}</main>
        <script src="/remember-login.js"></script>
        <script src="/mode-switch.js"></script>
        ${script}
      </body>
    </html>
  `;
}

const notice = (text) => `<div class="notice" role="status">✓ ${text}</div>`;

module.exports = { layout, modePanel, labDashboard, nav, notice };
