const select = (selector) => document.querySelector(selector);
const htmlEntities = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
const escapeHtml = (value) =>
  String(value ?? '').replace(/[&<>"']/g, (character) => htmlEntities[character]);
const revision = 'P7-persistent-profile-v3';
let testInfo;
let testsRunning = false;
const evidence = readEvidence();

function readEvidence() {
  try {
    const previous = JSON.parse(sessionStorage.getItem('hsd-evidence') || '{}');
    if (previous._revision === revision) return previous;
  } catch {}

  return {};
}

function persistEvidence() {
  try {
    sessionStorage.setItem('hsd-evidence', JSON.stringify(evidence));
  } catch {}
}

function getEvidenceKey(testId) {
  return testId === 'T1' || testId === 'T2' ? 'XSS' : testId;
}

async function requestJson(url, options) {
  const response = await fetch(url, options);
  if (!response.ok) throw new Error(`HTTP ${response.status}: ${await response.text()}`);
  return response.json();
}

async function getTestInfo() {
  testInfo = await requestJson('/lab/test-info', { cache: 'no-store' });
  if (testInfo.mode !== document.body.dataset.labMode)
    throw new Error(
      'Tryb serwera zmieniono na ' +
        testInfo.mode +
        ' (np. w Postmanie). Odśwież stronę, żeby uruchomić właściwy scenariusz.',
    );
  return testInfo;
}

function renderCodeBlock(label, value) {
  return `
    <div class="code-box">
      <b>${escapeHtml(label)}</b>
      <pre>${escapeHtml(value)}</pre>
    </div>`;
}

function renderComparison() {
  const labels = {
    XSS: 'XSS · wykonanie kodu',
    T3: 'CSRF · brak tokenu',
    T4: 'CSRF · błędny token',
    T5: 'Legalna zmiana · poprawny token',
    T6: 'CSP i cookie sesji',
  };
  const rows = Object.entries(labels).map(([key, label]) => {
    const cells = ['vulnerable', 'secure'].map((mode) => {
      const result = evidence[mode]?.[key];
      const summary = result
        ? escapeHtml(result.summary)
        : '<span class="muted">Nie wykonano</span>';

      return `<td>${summary}</td>`;
    });

    return `
      <tr>
        <th>${label}</th>
        ${cells.join('')}
      </tr>`;
  });

  select('#comparison-results').innerHTML = `
    <div class="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Scenariusz</th>
            <th>Przed ochroną</th>
            <th>Po zabezpieczeniu</th>
          </tr>
        </thead>
        <tbody>${rows.join('')}</tbody>
      </table>
    </div>`;
}

function saveEvidence(id, data) {
  const key = getEvidenceKey(id);
  evidence._revision = revision;
  evidence[testInfo.mode] ??= {};
  // Historia zawiera dane i obserwacje, bez tokenu CSRF i cookie sesji.
  const { visual, ...result } = data;
  evidence[testInfo.mode][key] = {
    ...result,
    id,
    mode: testInfo.mode,
    timestamp: new Date().toISOString(),
  };
  persistEvidence();
  renderComparison();
}

function renderTestResult(id, data) {
  const resultContainer = select(`#result-${id}`);
  resultContainer.querySelector('.running')?.remove();
  const preview = resultContainer.querySelector('.preview');
  let resultClass = 'fail';
  if (data.pass) resultClass = testInfo.mode === 'vulnerable' ? 'exposed' : 'pass';

  const outcome = document.createElement('div');
  outcome.className = 'outcome';
  outcome.innerHTML = `
    <h3>Rzeczywisty wynik tego uruchomienia</h3>
    <div class="result-banner ${resultClass}">
      <b>${data.pass ? '✓ Scenariusz potwierdzony' : '✕ Wynik niezgodny'}</b>
      <span>${escapeHtml(data.summary)}</span>
    </div>
    ${data.visual || ''}`;
  resultContainer.insertBefore(outcome, preview || resultContainer.firstChild);
  resultContainer.insertAdjacentHTML(
    'beforeend',
    `<div class="test-explanation">
      <p class="interpretation">${escapeHtml(data.why)}</p>
      <h3>Dokumentacja tego uruchomienia</h3>
      <p class="muted">
        Żądanie i odpowiedź poniżej pochodzą z tej próby. Cookie i poprawny token sesji pomijamy
        w eksporcie; Postman pobiera je po swoim logowaniu.
      </p>
      <div class="detail-grid">
        ${renderCodeBlock('Wysłane żądanie / opis', data.request)}
        ${renderCodeBlock('Odpowiedź HTTP / odczytana obserwacja', data.response)}
      </div>
      <p class="muted">
        Czas próby: ${escapeHtml(new Date().toLocaleString('pl-PL'))} · tryb ${escapeHtml(testInfo.mode)}
      </p>
    </div>`,
  );
  saveEvidence(id, data);
  return data.pass;
}

function resetXssEffect() {
  select('#app-header').classList.remove('xss-header');
  select('#xss-page-impact').hidden = true;
  select('#xss-page-impact').textContent = '';
  select('#xss-reset-area').hidden = true;
}

function getMainPageSnapshot() {
  return {
    headerClass: select('#app-header').className,
    bannerVisible: !select('#xss-page-impact').hidden,
    bannerText: select('#xss-page-impact').textContent,
  };
}

function getFrameSnapshot(frame, changes) {
  const frameDocument = frame.contentDocument;
  if (!frameDocument?.querySelector('#payload'))
    throw new Error('Brak oczekiwanej strony podglądu; sesja mogła wygasnąć.');
  return Object.fromEntries(
    changes.map((change) => [
      change.selector,
      change.selector === 'body'
        ? frameDocument.body.className
        : frameDocument.querySelector(change.selector)?.textContent,
    ]),
  );
}

function resizePreviewFrame(frame) {
  if (frame.contentDocument?.body)
    frame.style.height =
      Math.ceil(frame.contentDocument.body.getBoundingClientRect().height) + 24 + 'px';
}

async function loadPreviewFrame(frame, url) {
  await new Promise((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error('Podgląd nie załadował się w ciągu 8 sekund.')),
      8000,
    );
    frame.onload = () => {
      clearTimeout(timeout);
      resizePreviewFrame(frame);
      resolve();
    };
    frame.src = url;
  });
}

async function runXssTest(id) {
  const activeInfo = await getTestInfo();
  const spec = await requestJson('/lab/xss-info');
  resetXssEffect();
  const beforeMain = getMainPageSnapshot();

  const storedResponse = await fetch('/lab/xss-probe', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ description: spec.payload }),
  });
  const stored = await storedResponse.json();
  if (!storedResponse.ok || stored.payload !== spec.payload)
    throw new Error('Serwer nie potwierdził zapisu dokładnie tego payloadu.');

  const htmlResponse = await fetch(stored.frameUrl, { cache: 'no-store' });
  const rawHtml = await htmlResponse.text();
  if (htmlResponse.status !== 200)
    throw new Error('Odczyt opisu HTML: HTTP ' + htmlResponse.status);
  const resultContainer = select(`#result-${id}`);
  resultContainer.innerHTML = `
    <p class="running">
      Opis zapisany i odczytany z SQLite. Ładowanie strony przed i po wstawieniu opisu…
    </p>
    <div class="preview paired-preview">
      <section>
        <h3>PRZED · bez wstawionego payloadu</h3>
        <iframe data-frame="before" title="Strona przed wstawieniem payloadu" class="probe-frame"></iframe>
      </section>
      <section>
        <h3>PO · opis z bazy wstawiony do HTML</h3>
        <iframe data-frame="after" title="Strona po odczycie zapisanego payloadu" class="probe-frame"></iframe>
      </section>
    </div>`;
  const beforeFrame = resultContainer.querySelector('[data-frame=before]');
  const afterFrame = resultContainer.querySelector('[data-frame=after]');
  let executed = false;
  const handleExecution = (event) => {
    if (
      event.source === afterFrame.contentWindow &&
      event.origin === location.origin &&
      event.data === 'XSS_EXECUTED'
    )
      executed = true;
  };
  window.addEventListener('message', handleExecution);

  try {
    await loadPreviewFrame(beforeFrame, spec.baselineUrl);
    const before = getFrameSnapshot(beforeFrame, spec.changes);
    await loadPreviewFrame(afterFrame, stored.frameUrl + '?ts=' + Date.now());
    await new Promise((resolve) => setTimeout(resolve, 400));
    const observed = getFrameSnapshot(afterFrame, spec.changes);
    const afterMain = getMainPageSnapshot();
    const frameDocument = afterFrame.contentDocument;
    resizePreviewFrame(afterFrame);

    const textOnly =
      frameDocument.querySelector('#payload').textContent === stored.payload &&
      !frameDocument.querySelector('#payload img');
    const secure = activeInfo.mode === 'secure';
    const changesMatch = spec.changes.every(
      (change) => observed[change.selector] === (secure ? before[change.selector] : change.after),
    );
    const mainMatch = secure
      ? JSON.stringify(beforeMain) === JSON.stringify(afterMain)
      : afterMain.headerClass.includes('xss-header') && afterMain.bannerVisible;
    const pass =
      stored.stored && changesMatch && mainMatch && (secure ? !executed && textOnly : executed);
    select('#xss-reset-area').hidden = !executed;

    const rows = spec.changes.map((change) => ({
      element: change.label,
      selector: change.selector,
      before: before[change.selector],
      observed: observed[change.selector],
    }));
    rows.push({
      element: 'Kolor głównego nagłówka aplikacji',
      selector: 'parent #app-header.className',
      before: beforeMain.headerClass || '(bez klasy ataku)',
      observed: afterMain.headerClass || '(bez klasy ataku)',
    });
    rows.push({
      element: 'Komunikat na głównej stronie',
      selector: 'parent #xss-page-impact',
      before: beforeMain.bannerVisible ? beforeMain.bannerText : 'Ukryty',
      observed: afterMain.bannerVisible ? afterMain.bannerText : 'Ukryty',
    });
    const observationRows = rows.map(
      (row) => `
        <tr class="${row.before !== row.observed ? 'changed-row' : ''}">
          <th>${escapeHtml(row.element)}<small>${escapeHtml(row.selector)}</small></th>
          <td>${escapeHtml(row.before)}</td>
          <td>${escapeHtml(row.observed)}</td>
        </tr>`,
    );
    const pageImpact = secure
      ? 'Nie wystąpiła. Nagłówek i komunikat pozostały bez zmian.'
      : 'Nagłówek na górze strony jest teraz pomarańczowy. ' +
        'Bezpośrednio pod nagłówkiem pojawił się komunikat wstawiony przez payload.';
    const visual = `
      <div class="trace">
        <h3>Skąd pochodzi wykonany kod?</h3>
        <ol>
          <li>
            <b>Wysłano:</b> POST /lab/xss-probe, pole description
            (dokładny payload z instrukcji powyżej).
          </li>
          <li>
            <b>Serwer zapisał i odczytał:</b> SQLite → tabela
            <code>${escapeHtml(stored.storage.table)}</code> → user_id=${escapeHtml(stored.storage.record.user_id)}.
            Odczytany opis jest identyczny z wysłanym:
            <b>${stored.payload === spec.payload ? 'TAK' : 'NIE'}</b>.
          </li>
          <li>
            <b>Przeglądarka dostała:</b> GET /lab/xss-frame, HTTP ${htmlResponse.status}.
            Aktywne renderowanie: <code>${escapeHtml(spec.activeRenderer)}</code>.
          </li>
          <li>
            <b>Zaobserwowano:</b> wykonanie onerror: <b>${executed ? 'TAK' : 'NIE'}</b>;
            payload jako tekst: <b>${textOnly ? 'TAK' : 'NIE'}</b>.
          </li>
        </ol>
      </div>
      <h3>Rzeczywiste zmiany odczytane z elementów strony</h3>
      <div class="table-scroll">
        <table class="dom-observations">
          <thead>
            <tr>
              <th>Element / selektor</th>
              <th>Przed wstawieniem opisu</th>
              <th>Po wstawieniu opisu</th>
            </tr>
          </thead>
          <tbody>${observationRows.join('')}</tbody>
        </table>
      </div>
      <p class="expected">
        <b>Zmiana interfejsu głównej strony:</b>
        ${pageImpact}
        Podglądy poniżej pokazują obie wersje tej samej strony demo.
      </p>`;

    let summary = 'Nie potwierdzono oczekiwanego skutku.';
    if (executed) {
      summary =
        'Podatność potwierdzona — kod z opisu zmienił 5 elementów podglądu i 2 elementy głównej strony.';
    } else if (textOnly) {
      summary = 'Atak zatrzymany — payload jest tekstem; 7 obserwowanych elementów bez zmian.';
    }

    return renderTestResult(id, {
      pass,
      summary,
      visual,
      observations: rows,
      storage: stored.storage,
      javascriptExecuted: executed,
      renderedAsText: textOnly,
      why: secure
        ? 'Znaczniki opisu zakodowano jako tekst. Nie powstał element img z onerror. CSP jest dodatkową warstwą blokującą kod inline.'
        : 'Kod pochodzi z atrybutu onerror w opisie zapisanym w SQLite. Błąd ładowania obrazu uruchomił JavaScript. Zmiany DOM odczytaliśmy z obu dokumentów; niczego nie uznajemy na podstawie samego napisu „atak”.',
      request: [
        'POST /lab/xss-probe',
        'Content-Type: application/json',
        '',
        JSON.stringify({ description: spec.payload }, null, 2),
        '',
        'GET /lab/xss-frame',
      ].join('\n'),
      response: JSON.stringify(
        {
          postStatus: storedResponse.status,
          getHtmlStatus: htmlResponse.status,
          htmlContainsRawImage: rawHtml.includes('<img'),
          stored: stored.stored,
          storage: stored.storage,
          javascriptExecuted: executed,
          renderedAsText: textOnly,
          domObservations: rows,
        },
        null,
        2,
      ),
    });
  } finally {
    window.removeEventListener('message', handleExecution);
  }
}

function renderStateBox(label, state) {
  return `
    <div>
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(state?.display_name ?? 'Brak odczytu')}</strong>
      <small>${escapeHtml(state?.email ?? '')}</small>
    </div>`;
}

function showCandidate(id, candidate) {
  const preview = select(`#csrf-request-${id}`);
  preview.dataset.candidate = JSON.stringify(candidate);
  const body = { ...candidate };
  if (id === 'T4') body.csrfToken = 'INVALID-TOKEN';
  if (id === 'T5') body.csrfToken = '{{csrfToken}}';
  preview.textContent =
    'POST /lab/profile-probe\nContent-Type: application/json\nCookie: connect.sid=<cookie z logowania>\n\n' +
    JSON.stringify(body, null, 2);
}

async function runCsrfTest(id, tokenKind) {
  const activeInfo = await getTestInfo();
  const before = (await requestJson('/lab/profile-state')).profile;
  let candidate = JSON.parse(select(`#csrf-request-${id}`).dataset.candidate);
  if (candidate.display_name === before.display_name) {
    candidate = await requestJson('/lab/profile-candidate');
    showCandidate(id, candidate);
  }

  const body = { ...candidate };
  if (tokenKind === 'bad') body.csrfToken = 'INVALID-TOKEN';
  if (tokenKind === 'good') body.csrfToken = activeInfo.csrfToken;

  const response = await fetch('/lab/profile-probe', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const responseText = await response.text();
  let responseData = {};
  try {
    responseData = JSON.parse(responseText);
  } catch {}

  const state = await requestJson('/lab/profile-state');
  const after = state.profile;
  window.profileDemo.update(state);

  const expectedAcceptance = tokenKind === 'good' || activeInfo.mode === 'vulnerable';
  const accepted = response.ok;
  const profileUnchanged = JSON.stringify(before) === JSON.stringify(after);
  const matchesCandidate =
    after.display_name === candidate.display_name && after.email === candidate.email;
  const validResult = accepted
    ? responseData.changed === true &&
      responseData.persisted === true &&
      responseData.autoRestored === false &&
      matchesCandidate
    : response.status === 403 && profileUnchanged;
  const safeBody = { ...body };
  if (tokenKind === 'good') {
    safeBody.csrfToken = '{{csrfToken}} — pobrany z /lab/test-info w tej sesji';
  }

  const visual = accepted
    ? `
      <div class="state-diff">
        ${renderStateBox('PRZED ŻĄDANIEM · SELECT', responseData.before)}
        <span class="arrow">→</span>
        ${renderStateBox('PO UPDATE · SELECT', responseData.observed)}
        <span class="arrow">→</span>
        ${renderStateBox('AKTUALNY PROFIL · OSOBNY GET', after)}
      </div>
      <p class="expected">
        <b>HTTP ${response.status}.</b> Dane po ataku pozostają w bazie. Niezależny GET
        potwierdza wysłane imię, nazwisko i e-mail: <b>${matchesCandidate ? 'TAK' : 'NIE'}</b>.
        Automatyczne przywrócenie: <b>NIE</b>.
      </p>
      <div class="download-row">
        <button type="button" class="secondary" data-show-current-profile>
          Zobacz aktualny profil na tej stronie
        </button>
        <a class="primary-link" href="/profile" target="_blank" rel="noopener">
          Otwórz zapisany profil w nowej karcie →
        </a>
      </div>
      <p class="muted">
        Przywrócenie jest opcjonalne: osobny przycisk w panelu aktualnego profilu przywraca
        dane sprzed pierwszej zaakceptowanej próby.
      </p>`
    : `
      <div class="blocked-effect">
        <b>HTTP ${response.status} · ${escapeHtml(responseText)}</b>
        <p>
          Token został odrzucony. Wylosowane dane ${escapeHtml(candidate.display_name)} ·
          ${escapeHtml(candidate.email)} nie zostały zapisane.
        </p>
      </div>
      <div class="state-diff">
        ${renderStateBox('GET PRZED ŻĄDANIEM', before)}
        <span class="arrow">→</span>
        ${renderStateBox('GET PO ODRZUCENIU', after)}
      </div>
      <p class="expected"><b>Profil bez zmian:</b> ${profileUnchanged ? 'TAK' : 'NIE'}</p>`;

  let explanation =
    'HTTP 403 potwierdza odrzucenie żądania. Odczyty przed i po potwierdzają brak zmiany danych.';
  if (tokenKind === 'good') {
    explanation =
      'Poprawny token dopuścił legalny zapis. Dane pozostają w SQLite do kolejnego zapisu lub ręcznego przywrócenia.';
  } else if (accepted) {
    explanation =
      'Żądanie bez poprawnego tokenu zmieniło dane użytkownika. Wylosowany profil pozostaje zapisany i jest widoczny w zakładce Profil testowy, także po odświeżeniu.';
  }

  const acceptedAction = tokenKind === 'good' ? 'Legalny zapis' : 'Atak zaakceptowany';
  const profileStatus = profileUnchanged ? 'bez zmian' : 'ZMIENIONY';
  const result = renderTestResult(id, {
    pass: accepted === expectedAcceptance && validResult,
    summary: accepted
      ? `${acceptedAction} — ${after.display_name} · ${after.email}; zmiana pozostaje w profilu.`
      : `Żądanie odrzucone — HTTP ${response.status}; profil ${profileStatus}.`,
    visual,
    before,
    after,
    candidate,
    httpStatus: response.status,
    changed: responseData.changed ?? false,
    persisted: responseData.persisted ?? false,
    autoRestored: responseData.autoRestored ?? false,
    observed: responseData.observed ?? null,
    why: explanation,
    request: [
      'GET /lab/profile-state',
      'POST /lab/profile-probe',
      'Content-Type: application/json',
      'Cookie: [sesja po logowaniu]',
      '',
      JSON.stringify(safeBody, null, 2),
      '',
      'GET /lab/profile-state',
    ].join('\n'),
    response: [
      `HTTP ${response.status}`,
      responseText,
      '',
      'Niezależne odczyty profilu:',
      `before=${JSON.stringify(before)}`,
      `after=${JSON.stringify(after)}`,
      `unchanged=${profileUnchanged}`,
      `matchesSentData=${matchesCandidate}`,
    ].join('\n'),
  });

  try {
    showCandidate(id, await requestJson('/lab/profile-candidate'));
  } catch (error) {
    select(`#csrf-request-${id}`).textContent +=
      '\n\nNie udało się przygotować kolejnych danych: ' + error.message;
  }
  return result;
}

async function runSecurityHeadersTest() {
  const { mode, headers, cookie } = await getTestInfo();
  const secure = mode === 'secure';
  const https = location.protocol === 'https:';
  const headersMatch = secure
    ? !!headers.csp && headers.xContentType === 'nosniff' && !!headers.xFrame
    : !headers.csp;
  const pass =
    headersMatch &&
    cookie.httpOnly === true &&
    cookie.sameSite === (secure ? 'strict' : 'lax') &&
    cookie.secure === (secure && https);

  let secureCookieStatus = 'Nieaktywne · HTTP';
  if (cookie.secure) {
    secureCookieStatus = 'Aktywne';
  } else if (https) {
    secureCookieStatus = 'Wyłączone w tym trybie';
  }
  const httpsNote =
    secure && !https
      ? `
        <p class="expected">
          To zgodny wynik dla HTTP, ale nie pełne potwierdzenie cookie Secure.
          Uruchom HTTPS i powtórz T6 według zakładki „Instrukcja i Postman”.
        </p>`
      : '';
  const summaryParts = [
    `CSP ${headers.csp ? 'aktywna' : 'wyłączona'}`,
    `SameSite=${cookie.sameSite}`,
    `Secure=${cookie.secure}`,
  ];
  if (secure && !https) summaryParts.push('hardening HTTPS jeszcze niepotwierdzony');

  return renderTestResult('T6', {
    pass,
    summary: summaryParts.join(' · '),
    visual: `
      <div class="lab-grid">
        <div>
          <span>CSP</span>
          <b>${headers.csp ? 'Włączona' : 'Brak ochrony'}</b>
        </div>
        <div>
          <span>HttpOnly</span>
          <b>${cookie.httpOnly}</b>
        </div>
        <div>
          <span>SameSite</span>
          <b>${escapeHtml(cookie.sameSite)}</b>
        </div>
        <div>
          <span>Secure</span>
          <b>${secureCookieStatus}</b>
        </div>
      </div>
      ${httpsNote}`,
    headers,
    cookie,
    fullHttpsHardening: secure && https && cookie.secure,
    why: 'Nagłówki odczytano z aktywnej odpowiedzi serwera, a właściwości cookie z konfiguracji sesji. Postman pozwala dodatkowo sprawdzić rzeczywisty nagłówek Set-Cookie; test przeglądarkowy sprawdza flagi cookie zapisane przez Chrome.',
    request: 'GET /lab/test-info\nCookie: [sesja po logowaniu]',
    response: JSON.stringify(
      { httpStatus: 200, protocol: location.protocol, headers, cookie },
      null,
      2,
    ),
  });
}

function setTestsRunning(isRunning) {
  testsRunning = isRunning;
  document.querySelectorAll('.run-test,#run-all,[data-mode],#reset-xss').forEach((button) => {
    button.disabled = isRunning || button.dataset.unavailable === 'true';
  });
  window.profileDemo.setBusy(isRunning);
}

async function runTest(id) {
  const card = select(`#card-${id}`);
  card.classList.add('is-running');
  card.scrollIntoView({ behavior: 'smooth', block: 'start' });
  select(`#result-${id}`).innerHTML =
    '<p class="running" role="status">Wykonywanie rzeczywistego testu…</p>';
  try {
    switch (id) {
      case 'T1':
      case 'T2':
        return await runXssTest(id);
      case 'T5':
        return await runCsrfTest(id, 'good');
      case 'T4':
        return await runCsrfTest(id, 'bad');
      case 'T6':
        return await runSecurityHeadersTest();
      default:
        return await runCsrfTest(id, 'none');
    }
  } catch (error) {
    select(`#result-${id}`).innerHTML =
      `<div class="result-banner fail">Test nie został ukończony: ${escapeHtml(error.message)}</div>`;
    if (testInfo) {
      delete evidence[testInfo.mode]?.[getEvidenceKey(id)];
      persistEvidence();
      renderComparison();
    }
    return false;
  } finally {
    card.classList.remove('is-running');
  }
}

select('#reset-xss')?.addEventListener('click', resetXssEffect);
document.querySelectorAll('.run-test').forEach((button) =>
  button.addEventListener('click', async () => {
    if (testsRunning || button.dataset.unavailable === 'true') return;
    setTestsRunning(true);
    try {
      await runTest(button.dataset.test);
      select(`#result-${button.dataset.test}`).scrollIntoView({
        behavior: 'smooth',
        block: 'start',
      });
    } finally {
      setTestsRunning(false);
    }
  }),
);

select('#run-all').addEventListener('click', async () => {
  if (testsRunning) return;
  setTestsRunning(true);
  const ids = [...document.querySelectorAll('.run-test:not([data-unavailable])')].map(
    (button) => button.dataset.test,
  );
  let passed = 0;
  try {
    for (const [index, id] of ids.entries()) {
      select('#all-summary').textContent = `Trwa test ${index + 1}/${ids.length}: ${id}`;
      if (await runTest(id)) passed++;
    }
    const nextStep =
      testInfo.mode === 'vulnerable'
        ? 'Teraz włącz ochronę i powtórz testy.'
        : 'Sprawdź porównanie BEFORE → AFTER poniżej.';
    select('#all-summary').textContent =
      `${passed}/${ids.length} scenariuszy potwierdzonych. ${nextStep}`;
    select('#comparison-panel').open = true;
    select('#comparison-results').scrollIntoView({ behavior: 'smooth', block: 'start' });
  } finally {
    setTestsRunning(false);
  }
});

select('#export-report').addEventListener('click', () => {
  const blob = new Blob(
    [
      JSON.stringify(
        {
          project: 'P7 — Browser Hardening',
          exportedAt: new Date().toISOString(),
          scope: 'localhost; kontrolowane testy własnego konta',
          limitations: [
            'CSRF: test walidacji tokenu w tej samej sesji, nie dowód cross-site.',
            'HTTP: Secure cookie wymaga osobnego testu HTTPS.',
            'Dane sesji cookie pochodzą z konfiguracji serwera; sprawdź Set-Cookie w Postmanie.',
          ],
          results: evidence,
        },
        null,
        2,
      ),
    ],
    { type: 'application/json' },
  );
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'P7-evidence-before-after.json';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
renderComparison();

window.addEventListener('resize', () =>
  document.querySelectorAll('.probe-frame').forEach(resizePreviewFrame),
);
