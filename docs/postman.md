# P7 — dokładna instrukcja testów w Postmanie

Ta instrukcja dotyczy własnej aplikacji Hospital Service Desk na localhost. Konto i dane są laboratoryjne. Postman sprawdza odpowiedzi HTTP; przeglądarka dodatkowo sprawdza rzeczywiste wykonanie JavaScript.

## 1. Przygotowanie i import

1. Uruchom aplikację: `npm start`.
2. W Postmanie wybierz **Import**. Zaimportuj:
   - `postman/BAI-P7.postman_collection.json`,
   - `postman/localhost.postman_environment.json`.
3. Wybierz środowisko **BAI P7 — HTTP localhost**. `baseUrl` ma wartość `http://localhost:3000`.
4. Pozostaw włączony cookie jar. Kolekcja wyłącza automatyczne przekierowania, żeby status 302 logowania był widoczny.
5. Wysyłaj żądania w kolejności folderów **00 Start → 01 BEFORE → 02 AFTER**. Możesz użyć Runnera, uruchamiając całą kolekcję.
6. Oglądaj Body, Headers i wyniki testów każdego żądania. Wszystkie żądania mają opis celu i oczekiwanego wyniku.

Przeglądarka i Postman mają oddzielne cookie sesji. Zaloguj się osobno w obu. Tryb bezpieczeństwa jest globalny dla procesu Node.js — zmiana w Postmanie dotyczy także przeglądarki. Po zmianie odśwież otwartą stronę aplikacji. Nie mieszaj `localhost` z `127.0.0.1`.

## 2. Logowanie: konkretna sesja testowa

```http
POST {{baseUrl}}/login
Content-Type: application/json

{"username":"student","password":"student123"}
```

Oczekiwane: **HTTP 302**, `Location: /security-tests`, `Set-Cookie: connect.sid=...`. Cookie jar zapisuje cookie i wysyła je z następnymi żądaniami. Nie kopiuj wartości cookie z przykładu — serwer tworzy własną sesję.

Jeśli widzisz 302 do `/login` w żądaniu laboratoryjnym, nie masz aktywnej sesji w cookie jar. Powtórz logowanie na tym samym `baseUrl`.

## 3. BEFORE: włącz wersję podatną

```http
POST {{baseUrl}}/lab/mode
Content-Type: application/json

{"mode":"vulnerable"}
```

Oczekiwane: **200**, `{"ok":true,"mode":"vulnerable","reload":true}`. Endpoint wymaga JSON; z przeglądarki wymaga origin aplikacji. Postman nie musi wysyłać Origin.

Następnie:

```http
GET {{baseUrl}}/lab/profile-state
GET {{baseUrl}}/lab/test-info
```

Pierwsze żądanie odczytuje profil i zapisuje go w zmiennych `profileBefore` i `profileExpected`. Po zaakceptowanej zmianie `profileExpected` staje się nowym profilem; po odrzuceniu pozostaje bez zmian. Drugie zapisuje `csrfToken` jako zmienną kolekcji. W odpowiedzi `mode` musi być `vulnerable`.

## 4. T1/T2 Stored XSS: jaki kod, skąd i dlaczego działa?

1. `GET {{baseUrl}}/lab/xss-info` zwraca **pełny payload** w `payload`, sam JavaScript w `script`, selektory zmian w `changes` oraz aktywny sposób renderowania w `activeRenderer`.
2. `POST {{baseUrl}}/lab/xss-probe` przesyła dokładny opis w polu `description`. Pełny opis jest zapisany w Body gotowej kolekcji. Kod pochodzi z `src/security/lab-xss.js`; UI i kolekcja korzystają z tego samego payloadu.
3. Serwer zapisuje opis w tabeli SQLite `lab_payloads`, a następnie odczytuje rekord. Odpowiedź zawiera `stored=true` i `storage.record.description`. Porównaj go z polem `payload` poprzedniej odpowiedzi — muszą być identyczne.
4. `GET {{baseUrl}}/lab/xss-frame` ponownie odczytuje zapisany opis i wstawia go w odpowiedź HTML. Sprawdź Body → Raw.

Schemat payloadu (pełny kod jest w GET /lab/xss-info i w karcie T1/T2):

```html
<img src="/lab/missing-image" onerror="...dokładny JavaScript...">
```

`/lab/missing-image` nie istnieje. W podatnej stronie powstaje element `img`. Błąd pobrania obrazu wywołuje jego `onerror`, więc niezaufany opis wykonuje JavaScript.

Skrypt:

| Operacja | Dokładny element | Skutek |
| --- | --- | --- |
| `document.body.classList.add('compromised')` | body podglądu | Pomarańczowe tło i lewy pasek; CSS w public/style.css |
| `textContent = ...` | `#effect` | „Oryginalna strona zgłoszenia” → „ATAK XSS: kod z opisu zmienił tę stronę” |
| `textContent = ...` | `#demo-priority` | „Normalny” → „KRYTYCZNY — zmiana przez XSS” |
| `textContent = ...` | `#demo-owner` | „Dział IT” → „Kontrolowany payload XSS” |
| `textContent = ...` | `#demo-action` | „Wyślij zgłoszenie” → „Przycisk zmieniony przez XSS” |
| `parent.document...classList.add('xss-header')` | Główny `#app-header` | Pomarańczowy nagłówek całej aplikacji |
| `hidden=false; textContent=...` | Główny `#xss-page-impact` | Widoczny komunikat opisujący zmianę strony |
| `parent.postMessage(...)` | Wiadomość do testu | Znacznik `XSS_EXECUTED`, z weryfikacją source i origin |

To zmiany **DOM w przeglądarce**. Priorytet, opiekun i przycisk należą do kontrolowanego widoku demo, nie do rekordu zgłoszenia w bazie. XSS nie zmienia SQL. Serwer zapisuje tylko opis użyty w demonstracji.

**T1 BEFORE:** HTTP 200 i surowy `<img ... onerror=...>` w HTML. W przeglądarce — wykonanie kodu oraz siedem zmian odczytanych w tabeli.

**T2 AFTER:** HTTP 200 i zakodowane `&lt;img...&gt;`. W przeglądarce — opis jako tekst, brak elementu img, brak wykonania kodu i siedem obserwowanych elementów bez zmian. Bezpieczne renderowanie i CSP są aktywne równocześnie; demo nie rozdziela ich wpływu na osobne próby.

**Granica Postmana:** HTTP 200 albo obecność `<img>` nie potwierdzają wykonania JavaScript. Zaloguj się w przeglądarce i uruchom T1/T2 w laboratorium. Postman ma własną sesję; payload jest związany z kontem testowym, więc to samo konto może go odczytać w przeglądarce, ale samo otwarcie ramki nie tworzy tabeli obserwacji z laboratorium.

## Losowanie danych każdej próby

Przed T3, T4 i T5 kolekcja wykonuje `GET /lab/profile-candidate`. Zwraca fikcyjne `display_name` oraz unikalny `email` w domenie example.test i nie zmienia profilu. Skrypt ustawia `displayName` i `email`; żądania używają `{{displayName}}` i `{{email}}`. UI pokazuje dokładne wylosowane dane przed kliknięciem, a po próbie przygotowuje następne. Stałe przykłady poniżej wyjaśniają strukturę JSON; rzeczywista kolekcja wysyła wylosowane dane.

## 5. T3 — brak tokenu

```http
POST {{baseUrl}}/lab/profile-probe
Content-Type: application/json

{
  "display_name": "Profil zmieniony przez T3",
  "email": "t3-probe@example.test"
}
```

Cookie pochodzi z logowania. W Body celowo **nie ma** `csrfToken`.

**BEFORE:** HTTP **200**, `accepted=true`, `changed=true`, `persisted=true`, `autoRestored=false`. `before` to profil przed zapisem, `observed` to zmienione dane odczytane po UPDATE. Osobny `GET /lab/profile-state` potwierdza, że te dane pozostają w bazie.

**AFTER:** HTTP **403**, tekst `403 Forbidden - invalid CSRF token`. Osobny `GET /lab/profile-state` potwierdza, że profil nie zmienił się względem stanu sprzed tej próby (`profileExpected`).

Probe wykonuje UPDATE → SELECT i zatwierdza transakcję. Końcowy stan profilu to dane wysłane w próbie. Możesz otworzyć Profil testowy, odświeżyć stronę, a nawet zrestartować serwer — zapis pozostaje w SQLite. Kolejny zaakceptowany test nadpisze go kolejnym profilem. Pierwsza zaakceptowana próba zachowuje w `lab_profile_baselines` kopię profilu do opcjonalnego, ręcznego przywrócenia.

## 6. T4 — błędny token

```http
POST {{baseUrl}}/lab/profile-probe
Content-Type: application/json

{
  "display_name": "Profil zmieniony przez T4",
  "email": "t4-probe@example.test",
  "csrfToken": "INVALID-TOKEN"
}
```

**BEFORE:** HTTP **200**, zapis i odczyt zmiany; nowe dane pozostają w profilu.

**AFTER:** HTTP **403**, identyczny komunikat odrzucenia jak w T3; profil bez zmian.

## 7. AFTER — najpierw ochrona, następnie nowy token

```http
POST {{baseUrl}}/lab/mode
Content-Type: application/json

{"mode":"secure"}
```

Potem wykonaj `GET /lab/profile-state` i `GET /lab/test-info`. Poprzedni token po przełączeniu trybu jest unieważniony. Skrypt GET /lab/test-info zapisuje nowy `csrfToken`. Powtórz XSS, T3 i T4.

Rzeczywista funkcja `renderDescription` w app.js wybiera `escapeHtml(value)` dla trybu secure i `value` dla vulnerable. `verify` w src/security/csrf.js kończy żądanie kodem 403, jeśli w trybie secure nie ma poprawnego tokenu sesji.

## 8. T5 — poprawny token i legalna operacja

```http
POST {{baseUrl}}/lab/profile-probe
Content-Type: application/json

{
  "display_name": "Profil zmieniony przez T5",
  "email": "t5-probe@example.test",
  "csrfToken": "{{csrfToken}}"
}
```

Postman podstawia wartość zmiennej. Oczekiwane: HTTP **200**, `changed=true`, `persisted=true`, `autoRestored=false`, rzeczywiste zmienione dane w `observed`. Profil pozostaje zmieniony.

To potwierdza, że kontrola CSRF pozwala na prawidłowy zapis. Jeśli widzisz 403, pobierz token ponownie po przełączeniu trybu; używaj tego samego cookie jar.

## 9. T6 — pełne nagłówki i flagi cookie

```http
GET {{baseUrl}}/lab/test-info
```

Sprawdź **Headers**, a nie tylko JSON:

| Kontrola | BEFORE | AFTER HTTP | AFTER HTTPS |
| --- | --- | --- | --- |
| Content-Security-Policy | brak | obecna; script-src 'self', script-src-attr 'none' | obecna |
| X-Content-Type-Options | brak | nosniff | nosniff |
| X-Frame-Options | brak | SAMEORIGIN | SAMEORIGIN |
| Set-Cookie: HttpOnly | obecne | obecne | obecne |
| Set-Cookie: SameSite | Lax | Strict | Strict |
| Set-Cookie: Secure | brak | brak | obecne |

HttpOnly utrudnia odczyt cookie przez JavaScript; nie zapobiega XSS. SameSite ogranicza wysyłanie cookie z obcego site. Secure ogranicza wysyłanie cookie do HTTPS. CSP dodatkowo ogranicza wykonanie skryptów. Nagłówki nie są zamiennikami kodowania opisu i tokenu CSRF.

Serwer ponownie wysyła cookie po żądaniach zalogowanej sesji. Dzięki temu kolekcja weryfikuje rzeczywiste Set-Cookie, a nie wyłącznie deklarację JSON.

### HTTPS

Zatrzymaj poprzednie `npm start`, żeby zwolnić port 3000:

```sh
npm run https:cert
npm run start:https
```

Zaimportuj `postman/localhost-https.postman_environment.json` i wybierz **BAI P7 — HTTPS localhost**. `baseUrl=https://localhost:3443`. Dla tego samopodpisanego certyfikatu testowego wyłącz weryfikację certyfikatu w lokalnych żądaniach Postmana. Uruchom kolekcję od logowania.

T6 w secure powinien otrzymać Secure, HttpOnly i SameSite=Strict w Set-Cookie. HTTP z Secure=false jest zgodne z lokalnym HTTP, ale **nie potwierdza** spełnienia wymagania cookie Secure. Nie mieszaj obu protokołów w jednej sesji demo.

## 10. Żądanie z innego origin

```sh
npm run demo:csrf
```

Zaloguj się w przeglądarce na http://localhost:3000. Otwórz http://localhost:4000 i wyślij formularz bez tokenu. W wersji podatnej nowa karta pokaże zmieniony profil; po ochronie HTTP 403.

Ten ręczny formularz trafia do `/profile/update`; zmiana **pozostaje** w bazie. Automatyczne probe trafia do `/lab/profile-probe` i także pozostawia zapisane dane. To dwa sposoby demonstracji tego samego middleware verify. Opcjonalny przycisk przywraca kopię sprzed pierwszej zaakceptowanej próby probe; bez takiej kopii użyj legalnego formularza profilu.

Dwa porty to różne origin, ale ten sam site. To demo żądania z innego origin, nie dowód zachowania SameSite wobec obcej domeny. Postman nie egzekwuje przeglądarkowych ograniczeń SameSite, więc jego wyniki dotyczą kontroli tokenu i nagłówków, a nie pełnego zachowania przeglądarki.

## 11. Komendy cURL do Postmana i terminala

Aplikacja → **Instrukcja i Postman** zawiera komendy cURL do importowania przez Import → tekst. Cookie jar po logowaniu wysyła cookie automatycznie; T5 używa tokenu uzupełnionego przez gotową kolekcję.

Do terminala użyj kompletnego skryptu, który przenosi cookie między requestami i pobiera token:

```sh
sh scripts/demo-curl.sh http://localhost:3000
```

Wymagane cURL i Python 3. Skrypt pokazuje payload, pełne odpowiedzi i nagłówki, sprawdza utrzymanie zapisanej zmiany i zostawia serwer w trybie secure. Dane nie są przywracane automatycznie. Nie wykonuje kodu XSS w przeglądarce.

## 12. Odtwarzalne sprawdzenie kolekcji

```sh
npm test
npm run https:cert
npm run test:browser
npm run test:postman
```

Test Postmana pobiera runner Newman 6.2.2 przez npx (internet wymagany przy pierwszym uruchomieniu) i uruchamia tę samą kolekcję na osobnej bazie in-memory. Sprawdza HTTP oraz HTTPS, jeśli certyfikaty są dostępne. Nie zmienia danych użytkownika. Test przeglądarkowy sprawdza rzeczywisty DOM, obcy origin i cookie Chrome. Wyniki trafiają do evidence/.

Materiały techniczne i instrukcja nie zastępują raportu 8–12 stron ani przygotowania prezentacji wymaganych kartą projektu.

Mechanizm cookie jar i skrypty testowe opisuje oficjalna dokumentacja: [Postman cookies](https://learning.postman.com/docs/use/send-requests/response-data/cookies/), [Postman scripts](https://learning.postman.com/docs/tests-and-scripts/write-scripts/test-scripts/).

## Opcjonalne ręczne przywrócenie

PDF nie wymaga automatycznego restore. Główna kolekcja pozostawia wszystkie zaakceptowane zmiany. Przywrócenie w UI następuje wyłącznie po kliknięciu osobnego przycisku.

W Postmanie zaimportuj `postman/BAI-P7-manual-restore.postman_collection.json`. Uruchom ją osobno po demonstracji, z tym samym cookie jar. Kolekcja odczytuje kopię `initialProfile`, pobiera świeży token, wysyła `POST /lab/profile-restore` z `csrfToken` i sprawdza odczytem GET przywrócony stan. Token jest wymagany w obu trybach. Bez kopii endpoint zwraca 409. Pierwsza zaakceptowana próba probe tworzy kopię w SQLite; kolejne jej nie nadpisują, a ręczny restore ją usuwa.
