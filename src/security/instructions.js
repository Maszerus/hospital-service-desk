const { codeBlock } = require('./render');

function curlPost(endpoint, body) {
  return [
    `curl --request POST 'http://localhost:3000${endpoint}' \\`,
    "  --header 'Content-Type: application/json' \\",
    `  --data-raw '${JSON.stringify(body)}'`,
  ].join('\n');
}

function instructions() {
  return `
    <div class="eyebrow">P7 · INSTRUKCJA DO DEMONSTRACJI I ZALICZENIA</div>
    <h1>Każdy krok ma wejście, wynik i wyjaśnienie.</h1>
    <p>
      Tu znajdziesz dokładne żądania, kolejność testów, znaczenie kodu i kryteria BEFORE →
      AFTER. Wszystkie testy dotyczą tej aplikacji na localhost.
    </p>
    <section class="instructions">
      <h2>1. Demo w przeglądarce — wykonanie JavaScript</h2>
      <ol>
        <li>
          Zaloguj się jako <code>student</code> / <code>student123</code>. Wejdź do
          laboratorium i wybierz „Przed ochroną”.
        </li>
        <li>
          W karcie T1 najpierw przeczytaj „Dokładny payload”. To cały opis, który serwer
          zapisze w SQLite, łącznie z kodem JavaScript w <code>onerror</code>.
        </li>
        <li>
          Kliknij „Wykonaj atak XSS”. Zobacz dwa podglądy: przed wstawieniem opisu i po
          odczytaniu go z bazy. Tytuł, priorytet, opiekun, tekst przycisku i wygląd drugiego
          podglądu się zmienią. Główny nagłówek aplikacji też zmieni kolor, a na tej stronie
          pojawi się komunikat wstawiony przez payload.
        </li>
        <li>
          Tabela odczytuje rzeczywisty DOM. To nie są oczekiwane wartości przepisane do
          wyniku; oczekiwania są opisane przed testem.
        </li>
        <li>
          Kliknij T3 i T4. Widzisz żądanie, odpowiedź HTTP i profil przed zmianą, po UPDATE
          oraz w niezależnym odczycie. Zmiana pozostaje w bazie; panel aktualnego profilu
          pokazuje nowe imię, nazwisko i e-mail. Ręczne przywrócenie ma osobny przycisk.
        </li>
        <li>
          Włącz „Po zabezpieczeniu”. Uruchom T2, T3, T4, T5 i T6. T2 pokaże kod jako tekst i
          brak zmian strony; T3/T4 dostaną 403 i potwierdzą profil bez zmian; T5 dopuści
          poprawny token.
        </li>
      </ol>
      <p class="expected">
        <b>Co odróżnia XSS od CSRF?</b> XSS wykonuje JavaScript z niezaufanego opisu w
        przeglądarce. CSRF polega na wymuszeniu żądania w aktywnej sesji. Nie jest do tego
        potrzebne wykonanie kodu z opisu.
      </p>
    </section>
    <section class="instructions" id="postman">
      <h2>2. Postman — gotowy zestaw żądań</h2>
      <div class="download-row">
        <a class="primary-link" href="/lab/download/postman">Pobierz kolekcję Postmana</a>
        <a class="primary-link" href="/lab/download/manual-restore">
          Osobna kolekcja ręcznego restore
        </a>
        <a class="primary-link" href="/lab/download/http-env">Środowisko HTTP</a>
        <a class="primary-link" href="/lab/download/https-env">Środowisko HTTPS</a>
        <a class="primary-link" href="/lab/download/manual">Instrukcja Markdown</a>
      </div>
      <ol>
        <li>
          W Postmanie wybierz <b>Import</b> i wskaż kolekcję oraz środowisko HTTP. Wybierz
          środowisko <b>BAI P7 — HTTP localhost</b>;
          <code>baseUrl=http://localhost:3000</code>.
        </li>
        <li>
          Wykonuj foldery w kolejności: <b>00 Start</b>, <b>01 BEFORE</b>, <b>02 AFTER</b>.
          Możesz wysyłać pojedyncze żądania albo uruchomić kolekcję przez Runner.
        </li>
        <li>
          Logowanie wysyła POST /login. Oczekiwane <b>302</b> i
          <b>Set-Cookie: connect.sid=...</b>; przekierowania są wyłączone dla żądań kolekcji,
          cookie jar pozostaje włączony.
        </li>
        <li>
          Postman automatycznie wysyła zapisane cookie z kolejnymi żądaniami. Nie trzeba
          kopiować cookie z przeglądarki. Sesja Postmana i sesja przeglądarki są oddzielne.
          Tryb procesu jest wspólny: po zmianie w Postmanie odśwież otwartą stronę
          przeglądarki.
        </li>
        <li>
          Przed T3, T4 i T5 GET /lab/profile-candidate losuje fikcyjne dane i zapisuje zmienne
          displayName i email. Body używa {{displayName}} i {{email}}. Skrypt odpowiedzi GET
          /lab/test-info zapisuje <code>csrfToken</code>. Żądanie T5 używa
          <code>{{csrfToken}}</code>. Po zmianie trybu pobieramy nowy token, bo poprzedni
          został unieważniony.
        </li>
        <li>
          Każde żądanie ma opis i automatyczne testy odpowiedzi. Sprawdź <b>Body</b>,
          <b>Headers</b> i wyniki testów; nie ograniczaj się do zielonej ikony.
        </li>
      </ol>
      <p class="expected">
        <b>Postman a XSS:</b> odpowiedź HTML pokazuje dokładnie, co serwer zwrócił. Postman
        sprawdza zapis i kodowanie, ale nie dowodzi wykonania JavaScript w przeglądarce. Do
        dowodu wykonania uruchom T1/T2 w przeglądarce. Sam HTTP 200 nie oznacza sukcesu XSS.
      </p>
      <div class="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Żądanie</th>
              <th>PRZED</th>
              <th>PO</th>
              <th>Co oglądać</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <th>POST /lab/xss-probe</th>
              <td>200, stored=true</td>
              <td>200, stored=true</td>
              <td>storage.record.description równe wysłanemu payloadowi</td>
            </tr>
            <tr>
              <th>GET /lab/xss-frame</th>
              <td>200, surowe &lt;img ... onerror=...&gt;</td>
              <td>200, zakodowane &amp;lt;img ...&amp;gt;</td>
              <td>Body → Raw; wykonanie potwierdza przeglądarka</td>
            </tr>
            <tr>
              <th>POST /lab/profile-probe bez tokenu</th>
              <td>200, zmiana profilu pozostaje w bazie</td>
              <td>403, brak zmiany profilu</td>
              <td>before, observed oraz osobny GET aktualnego profilu</td>
            </tr>
            <tr>
              <th>POST /lab/profile-probe z INVALID-TOKEN</th>
              <td>200, zmiana profilu pozostaje w bazie</td>
              <td>403, brak zmiany profilu</td>
              <td>Status i komunikat odrzucenia</td>
            </tr>
            <tr>
              <th>POST /lab/profile-probe z poprawnym tokenem</th>
              <td>Nie jest wymagany do baseline</td>
              <td>200, changed=true, persisted=true, autoRestored=false</td>
              <td>Token pochodzi z aktualnej sesji</td>
            </tr>
            <tr>
              <th>GET /lab/test-info</th>
              <td>Brak CSP, SameSite=Lax</td>
              <td>CSP, SameSite=Strict</td>
              <td>Headers → Set-Cookie, CSP, nosniff, SAMEORIGIN</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
    <section class="instructions">
      <h2>Ręczne przywrócenie jest opcjonalne</h2>
      <p>
        PDF wymaga demonstracji ryzyka i BEFORE → AFTER; nie wymaga automatycznego restore.
        Główna kolekcja i przyciski testów pozostawiają zaakceptowane zmiany. Przycisk w
        panelu profilu wysyła osobny POST /lab/profile-restore z poprawnym tokenem w obu
        trybach. Przywraca kopię sprzed pierwszej zaakceptowanej próby i usuwa tę kopię. W
        Postmanie uruchom oddzielną kolekcję ręcznego restore tylko na swoje żądanie.
      </p>
    </section>
    <section class="instructions">
      <h2>3. Komendy do importu w Postmanie</h2>
      <p>
        Import → wklej tekst cURL. Zaloguj się najpierw w Postmanie, pozostaw włączony cookie
        jar i używaj wszędzie <code>localhost</code>. Te komendy można importować pojedynczo;
        gotowa kolekcja dodatkowo uzupełnia token i sprawdza odpowiedzi.
      </p>
      ${codeBlock(
        'Logowanie — zapis cookie sesji w Postmanie',
        curlPost('/login', { username: 'student', password: 'student123' }),
      )}
      ${codeBlock('Wersja podatna — HTTP 200', curlPost('/lab/mode', { mode: 'vulnerable' }))}
      ${codeBlock(
        'T3 — brak tokenu: przed 200, po 403',
        curlPost('/lab/profile-probe', {
          display_name: 'Profil zmieniony przez T3',
          email: 't3-probe@example.test',
        }),
      )}
      ${codeBlock(
        'T4 — błędny token: przed 200, po 403',
        curlPost('/lab/profile-probe', {
          display_name: 'Profil zmieniony przez T4',
          email: 't4-probe@example.test',
          csrfToken: 'INVALID-TOKEN',
        }),
      )}
      ${codeBlock(
        'Włączenie ochrony — unieważnia poprzedni token',
        curlPost('/lab/mode', { mode: 'secure' }),
      )}
      ${codeBlock(
        'Pobranie tokenu i nagłówków dla aktualnej sesji',
        "curl --request GET 'http://localhost:3000/lab/test-info'",
      )}
      ${codeBlock(
        'T5 — w gotowej kolekcji zmienna jest uzupełniana automatycznie',
        curlPost('/lab/profile-probe', {
          display_name: 'Profil zmieniony przez T5',
          email: 't5-probe@example.test',
          csrfToken: '{{csrfToken}}',
        }),
      )}
      <p>
        <b>Uwaga do komend:</b> cookie jar Postmana wysyła cookie po logowaniu. W terminalu te
        komendy bez <code>-b</code> nie przeniosą sesji; do terminala pobierz i uruchom
        kompletny skrypt poniżej.
      </p>
      <a class="primary-link" href="/lab/download/curl">Pobierz kompletny skrypt cURL</a>
    </section>
    <section class="instructions" id="https">
      <h2>4. HTTPS i rzeczywiste flagi cookie</h2>
      ${codeBlock(
        'Terminal — uruchomienie HTTPS',
        ['npm run https:cert', 'npm run start:https'].join('\n'),
      )}
      <ol>
        <li>
          Zatrzymaj poprzednie npm start, aby zwolnić port 3000, i uruchom start:https.
          Aplikacja działa równocześnie na HTTP:3000 i HTTPS:3443.
        </li>
        <li>
          W Postmanie wybierz środowisko <b>BAI P7 — HTTPS localhost</b>. Dla samopodpisanego
          certyfikatu tego localhost wyłącz weryfikację certyfikatu w ustawieniach żądań
          testowych.
        </li>
        <li>
          Uruchom kolekcję od logowania. W trybie secure T6 ma pokazać
          <code>Secure=true</code>, a nagłówek <code>Set-Cookie</code> zawierać
          <code>Secure; HttpOnly; SameSite=Strict</code> (kolejność flag może być inna).
        </li>
        <li>
          W HTTP Secure=false jest oczekiwane, ale nie potwierdza spełnienia wymagania HTTPS.
          Obie sytuacje są opisane w T6.
        </li>
      </ol>
    </section>
    <section class="instructions">
      <h2>5. Ręczny CSRF z innej strony</h2>
      ${codeBlock('Terminal — druga strona localhost', 'npm run demo:csrf')}
      <p>
        Zaloguj się na http://localhost:3000, otwórz http://localhost:4000 i wyślij formularz.
        Przed ochroną nowa karta pokaże zmieniony profil; po ochronie — HTTP 403. Ten ręczny
        zapis pozostaje w bazie, więc przywróć dane formularzem profilu.
      </p>
      <p>
        <b>Origin a site:</b> dwa porty oznaczają różne origin, ale ten sam site. To
        demonstracja tokenu CSRF wobec żądania z innego origin. Nie pokazuje ona zachowania
        SameSite wobec obcej domeny.
      </p>
    </section>
    <section class="instructions">
      <h2>6. Gdzie jest kod i jak odtworzyć testy?</h2>
      <ul>
        <li>
          <code>src/security/lab-xss.js</code> — jeden dokładny payload, jego JavaScript i
          oczekiwane zmiany.
        </li>
        <li>
          <code>app.js</code> — zapis i odczyt payloadu, wspólne renderowanie opisów,
          transakcja profilu, nagłówki i ustawienia cookie.
        </li>
        <li><code>src/security/csrf.js</code> — tworzenie tokenu i weryfikacja.</li>
        <li><code>src/security/render.js</code> — kodowanie tekstu HTML.</li>
        <li>
          <code>public/security-tests.js</code> — rzeczywiste żądania i obserwacja DOM, nie
          symulacja zmian.
        </li>
        <li>
          <code>postman/BAI-P7.postman_collection.json</code> — żądania, opisy i testy
          odpowiedzi.
        </li>
      </ul>
      ${codeBlock(
        'Sprawdzenie aplikacji i kolekcji',
        ['npm test', 'npm run test:browser', 'npm run test:postman'].join('\n'),
      )}
      <p>
        Testy automatyczne korzystają z własnej bazy in-memory. Raport 8–12 stron i
        przygotowanie obrony pozostają osobnymi elementami zaliczenia; ta instrukcja opisuje
        techniczną demonstrację.
      </p>
    </section>
  `;
}

module.exports = { instructions };
