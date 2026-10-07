const { escapeHtml, codeBlock } = require('./render');
const { verify } = require('./csrf');
const xss = require('./lab-xss');

function testGuide(id, mode, candidate) {
  const secure = mode === 'secure';

  if (id === 'T1' || id === 'T2') {
    return renderXssGuide(id, secure);
  }

  if (id === 'T6') {
    return renderHeadersGuide();
  }

  return renderCsrfGuide(id, secure, candidate);
}

function renderXssGuide(id, secure) {
  const expectedResult = secure
    ? 'HTTP 200, payload widoczny jako tekst, brak elementu img i brak wykonania onerror. Wszystkie elementy strony pozostają takie jak przed próbą.'
    : 'HTTP 200, wykonanie onerror i widoczne zmiany elementów strony. To potwierdzenie podatności, nie bezpieczeństwa.';

  return `
    <div class="scenario-guide">
      <h3>Co dokładnie uruchomisz?</h3>
      <p>
        <b>Źródło danych:</b> poniższy opis wysyłamy w polu <code>description</code> do
        <code>POST /lab/xss-probe</code>. Serwer zapisuje go w tabeli
        <code>lab_payloads</code> dla Twojego konta. <code>GET /lab/xss-frame</code> odczytuje
        ten sam opis i wstawia go do HTML.
      </p>
      ${codeBlock('Dokładny payload — to cały opis zapisywany w SQLite', xss.payload)}
      <ol class="explained-steps">
        <li>
          <code>&lt;img&gt;</code> jest elementem HTML, a <code>onerror</code> jego obsługą
          błędu w JavaScript.
        </li>
        <li>
          Obraz <code>/lab/missing-image</code> nie istnieje (HTTP 404). W trybie podatnym
          przeglądarka wywołuje <code>onerror</code>.
        </li>
        <li>
          <code>classList.add</code> zmienia wygląd; <code>textContent</code> zmienia tytuł,
          priorytet, opiekuna i tekst przycisku w podglądzie.
        </li>
        <li>
          <code>parent.document</code> sięga do tej strony: zmienia kolor głównego nagłówka i
          pokazuje komunikat demo. Ramka ma ten sam origin co aplikacja.
        </li>
        <li>
          <code>postMessage</code> wysyła znacznik wykonania do testu. Wynik potwierdzamy
          także odczytem rzeczywistych elementów DOM.
        </li>
      </ol>
      <div class="detail-grid">
        ${codeBlock(
          'Rzeczywista funkcja · app.js / renderDescription',
          [
            "const renderDescription=value=>currentMode==='secure'?escapeHtml(value):value;",
            '// vulnerable: aktywna jest gałąź value (surowy HTML)',
          ].join('\n'),
        )}
        ${codeBlock(
          'Aktywna ochrona w trybie secure',
          [
            'escapeHtml(value)',
            '// < staje się &lt;, > staje się &gt;',
            "// Helmet dodatkowo wysyła CSP: script-src 'self'; script-src-attr 'none'",
          ].join('\n'),
        )}
      </div>
      <p class="expected"><b>Oczekiwany wynik ${id}:</b> ${expectedResult}</p>
      <p>
        <b>Co jest zmieniane?</b> Tylko interfejs przeglądarki (DOM). Baza przechowuje opis z
        payloadem; skrypt nie zmienia rekordów profilu ani zgłoszeń.
      </p>
      <a href="/instructions#postman">Odtwórz T1/T2 w Postmanie i przeglądarce →</a>
    </div>
  `;
}

function renderHeadersGuide() {
  return `
    <div class="scenario-guide">
      <h3>Co dokładnie sprawdzamy?</h3>
      <p>
        <code>GET /lab/test-info</code> odczytuje aktywne nagłówki serwera i konfigurację
        sesji. Poniżej pojawią się pełne wartości odpowiedzi, a nie same skróty ON/OFF.
      </p>
      <div class="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Kontrola</th>
              <th>Znaczenie</th>
              <th>Oczekiwane po ochronie</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <th>CSP</th>
              <td>Ogranicza źródła skryptów i blokuje kod inline.</td>
              <td>script-src 'self'; script-src-attr 'none'</td>
            </tr>
            <tr>
              <th>X-Content-Type-Options</th>
              <td>Zapobiega zgadywaniu typu treści.</td>
              <td>nosniff</td>
            </tr>
            <tr>
              <th>X-Frame-Options</th>
              <td>Ogranicza osadzanie strony w ramkach innych origin.</td>
              <td>SAMEORIGIN</td>
            </tr>
            <tr>
              <th>HttpOnly</th>
              <td>JavaScript nie może odczytać cookie sesji.</td>
              <td>true</td>
            </tr>
            <tr>
              <th>SameSite</th>
              <td>Ogranicza wysyłanie cookie w żądaniach z obcego site.</td>
              <td>Strict</td>
            </tr>
            <tr>
              <th>Secure</th>
              <td>Cookie jest wysyłane wyłącznie po HTTPS.</td>
              <td>true po HTTPS; HTTP nie potwierdza tej kontroli</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p class="expected">
        <b>Oczekiwany wynik:</b> HTTP 200. W wersji podatnej brak CSP i SameSite=Lax; po
        ochronie CSP i SameSite=Strict. HttpOnly pozostaje aktywne w obu wersjach. Flaga
        Secure wymaga testu HTTPS.
      </p>
      <a href="/instructions#https">Jak sprawdzić rzeczywiste Set-Cookie w Postmanie →</a>
    </div>
  `;
}

function renderCsrfGuide(id, secure, candidate) {
  const body = { ...candidate };
  let goal = 'sprawdzić, czy serwer odrzuca zapis bez tokenu.';

  if (id === 'T4') {
    body.csrfToken = 'INVALID-TOKEN';
    goal = 'sprawdzić, czy serwer wykrywa błędny token.';
  }

  if (id === 'T5') {
    body.csrfToken = '{{csrfToken}}';
    goal = 'potwierdzić, że poprawny token pozwala na legalny zapis.';
  }

  const request = [
    'POST /lab/profile-probe',
    'Content-Type: application/json',
    'Cookie: connect.sid=<cookie z logowania>',
    '',
    JSON.stringify(body, null, 2),
  ].join('\n');
  const tokenHint =
    id === 'T5'
      ? `
    <p>
      <code>{{csrfToken}}</code> to zmienna Postmana uzupełniana z odpowiedzi
      <code>GET /lab/test-info</code>. Nie wpisuj dosłownie nawiasów jako tokenu.
    </p>
  `
      : '';
  const expectedResult =
    id === 'T5' || !secure
      ? 'HTTP 200, changed=true, persisted=true, autoRestored=false; odpowiedź zawiera before i observed. Nowy profil pozostaje zapisany.'
      : 'HTTP 403; odpowiedź „403 Forbidden - invalid CSRF token”; profil przed i po identyczny.';

  return `
    <div class="scenario-guide">
      <h3>Co dokładnie wyślemy?</h3>
      <p>
        <b>Cel:</b> ${goal} Najpierw odczytamy profil przez
        <code>GET /lab/profile-state</code>, a następnie wyślemy poniższe żądanie.
      </p>
      <p>
        <b>Losowe, fikcyjne dane do następnej próby:</b> imię i nazwisko oraz unikalny e-mail
        w domenie example.test. Poniższy JSON jest dokładnym wejściem; po próbie wygenerujemy
        kolejne dane.
      </p>
      <div class="code-box">
        <b>Żądanie następnej próby (dane są już wylosowane)</b>
        <pre
          id="csrf-request-${id}"
          data-candidate="${escapeHtml(JSON.stringify(candidate))}"
        >${escapeHtml(request)}</pre>
      </div>
      ${tokenHint}
      ${codeBlock('Rzeczywista funkcja kontroli · src/security/csrf.js', verify.toString())}
      <ol class="explained-steps">
        <li>Cookie sesji identyfikuje zalogowanego użytkownika.</li>
        <li>
          W wersji podatnej <code>verify</code> przepuszcza żądanie. Po ochronie porównuje
          token z tokenem tej sesji.
        </li>
        <li>
          Jeśli zapis jest dopuszczony, serwer wykonuje UPDATE profilu → SELECT zmienionych
          danych i zatwierdza transakcję. Zmiana pozostaje w SQLite, także po odświeżeniu
          strony. Przed pierwszą zaakceptowaną próbą zachowujemy profil początkowy do ręcznego
          przywrócenia.
        </li>
        <li>
          Jeśli kontrola odrzuci żądanie, dostaniesz HTTP 403. Profil odczytujemy ponownie i
          sprawdzamy, czy pozostał bez zmian.
        </li>
      </ol>
      <p class="expected">
        <b>Oczekiwany wynik ${id} w tym trybie:</b> ${expectedResult}
      </p>
      <p>
        <b>Granica demonstracji:</b> ten przycisk sprawdza token w żądaniu z tej samej
        aplikacji. Formularz na drugim porcie osobno pokazuje żądanie z innego origin.
        SameSite to osobna kontrola.
      </p>
      <a href="/instructions#postman">Odtwórz ${id} w Postmanie →</a>
    </div>
  `;
}

module.exports = { testGuide };
