# Hospital Service Desk · P7 Browser Hardening

Lokalne laboratorium projektu BAI: widoczny atak XSS, zmiana danych przez żądanie bez tokenu CSRF, włączenie zabezpieczeń i porównanie BEFORE → AFTER. Node.js + Express + SQLite + HTML/CSS/JavaScript.

## Uruchomienie

Wymagany Node.js 20+.

```sh
npm ci
# Przy pierwszym uruchomieniu, jeśli brak .env:
cp .env.example .env
npm start
```

Otwórz http://localhost:3000. Konto: `student` / `student123`. Po logowaniu otwiera się laboratorium. Serwer nasłuchuje tylko na interfejsie loopback.

## Instrukcja i Postman

Po logowaniu otwórz zakładkę **Instrukcja i Postman**. Zawiera kolejność demonstracji, oczekiwane statusy, pełny opis mechanizmów oraz pliki do pobrania:

- [Kolekcja Postmana](postman/BAI-P7.postman_collection.json) — żądania, automatyczne logowanie/cookie, pobranie tokenu oraz asercje BEFORE/AFTER.
- [Środowisko HTTP](postman/localhost.postman_environment.json) i [HTTPS](postman/localhost-https.postman_environment.json).
- [Pełna instrukcja testów](docs/postman.md), obejmująca wszystkie wejścia, odpowiedzi i ograniczenia testów.
- [Kompletny skrypt cURL do terminala](scripts/demo-curl.sh); komendy do importowania pojedynczo w Postmanie są też w aplikacji.

Przed każdym testem aplikacja pokazuje dokładny payload lub żądanie, kod kontroli oraz oczekiwany wynik. Po teście pokazuje odpowiedź i rzeczywiste obserwacje. Przy XSS porównuje pięć elementów podglądu oraz dwa elementy głównej strony; nagłówek i komunikat zmienione przez payload są widoczne podczas przewijania. Kod nie zmienia SQL; widok demonstracyjny ma jawne oznaczenie.

Postman sprawdza zapis i odpowiedź HTML. Wykonanie JavaScript potwierdza osobny test w przeglądarce. Tryb bezpieczeństwa jest wspólny dla procesu — po zmianie trybu przez Postmana odśwież stronę w przeglądarce.

## Demo w trzy kroki

1. Wybierz **Przed ochroną** i **Uruchom wszystkie testy**. T1 pokazuje cały kod i zmienia tytuł, priorytet, opiekuna, tekst przycisku oraz wygląd podglądu, a także główny nagłówek i komunikat aplikacji; T3/T4 pokazują dane przed zmianą, po zapisie do bazy i w niezależnym odczycie aktualnego profilu. Potwierdzony scenariusz podatności ma bursztynowy wynik.
2. Wybierz **Po zabezpieczeniu** i uruchom testy ponownie. T2 pokazuje payload jako tekst, T3/T4 zwracają 403, a T5 potwierdza legalną zmianę z poprawnym tokenem.
3. Sprawdź tabelę porównania i kliknij **Pobierz dowody JSON**. Żądania i odpowiedzi są od razu widoczne pod testami. Wyniki są zachowywane w `sessionStorage` tej karty; zamknięcie karty usuwa tę historię.

Przy pojedynczym teście aplikacja przewija do jego widocznego wyniku. Podczas testów przełączanie trybu jest zablokowane. Zgłoszenia i profil mają formularze oraz komunikaty potwierdzające zapis.

## Co faktycznie jest testowane

| Test | Przed ochroną | Po zabezpieczeniu |
| --- | --- | --- |
| T1/T2 Stored XSS | Payload zapisany w `lab_payloads`, odczytany z SQLite i wykonany w widocznym iframe | Ten sam payload renderowany przez `escapeHtml`, wyświetlony jako tekst; dodatkowa CSP |
| T3 Brak tokenu CSRF | Zapis profilu zaakceptowany | HTTP 403 przed zapisem |
| T4 Błędny token | Zapis profilu zaakceptowany | HTTP 403 przed zapisem |
| T5 Poprawny token | Test legalnej operacji prezentowany w trybie secure | Zapis zaakceptowany, kontrola nie blokuje prawidłowego żądania |
| T6 Nagłówki i sesja | Baseline bez CSP, HttpOnly, SameSite=Lax | CSP, nosniff, X-Frame-Options, HttpOnly, SameSite=Strict; Secure przy HTTPS |

Test XSS używa tej samej funkcji renderowania opisów co lista zgłoszeń. Osobna tabela laboratoryjna pozwala pokazać skutek bez zaśmiecania zgłoszeń użytkownika. Ręczny payload w formularzu nowego zgłoszenia: `<script src="/xss-demo.js"></script>`; w wersji podatnej zmieni nagłówek strony, w zabezpieczonej będzie tekstem.

Automatyczne testy CSRF wykonują żądania w tej samej sesji i sprawdzają walidację tokenu. Zapis i odczyt profilu są jedną transakcją; zmiana zostaje w SQLite. Wynik potwierdza osobny GET aktualnego profilu. Pierwsza zaakceptowana próba zachowuje kopię danych początkowych; opcjonalny przycisk przywraca je na żądanie, z poprawnym tokenem w obu trybach. Nie jest to samodzielny dowód ataku z obcej domeny. Test T6 w interfejsie odczytuje nagłówki i konfigurację cookie po stronie serwera; test przeglądarkowy dodatkowo sprawdza rzeczywiste Set-Cookie i cookie zapisane przez Chrome.

## Formularz CSRF z innego origin

```sh
npm run demo:csrf
```

Zaloguj się na **http://localhost:3000**, następnie otwórz **http://localhost:4000**. Kliknij wysłanie żądania bez tokenu. Nowa karta pokaże zmieniony profil w wersji podatnej albo 403 po włączeniu ochrony. W ręcznym demo dane pozostają zmienione; przywróć je formularzem profilu.

Oba adresy mają ten sam site, ale różne origin (porty). Pozwala to oddzielnie wykazać znaczenie tokenu CSRF. SameSite=Lax może już blokować POST z rzeczywiście obcej domeny w wersji podatnej, więc nie opisujemy każdego takiego POST jako skutecznego ataku. Dla obu kart używaj `localhost`; nie mieszaj z `127.0.0.1`.

## Lokalne HTTPS i flaga Secure

```sh
npm run https:cert
npm run start:https
```

Otwórz https://localhost:3443, zaakceptuj lokalny certyfikat testowy, zaloguj się i włącz **Po zabezpieczeniu**. Uruchom T6. W DevTools → Network sprawdź Set-Cookie, a w Application → Cookies: `HttpOnly`, `Secure`, `SameSite=Strict`. Certyfikat jest samopodpisany, ważny 30 dni i przeznaczony do tego lokalnego laboratorium. Klucze w `.certs/` są ignorowane przez Git. Skrypt certyfikatu wymaga OpenSSL z obsługą `-addext`.

HTTP pozostaje dostępne na porcie 3000, HTTPS na 3443. Secure jest włączane tylko dla trybu secure i połączenia HTTPS. Przełącznik zmienia globalny tryb procesu bez restartu; `.env` ustawia tryb początkowy. Do porównań używaj jednej sesji i jednego protokołu.

## Weryfikacja

```sh
npm test
npm run https:cert
npm run test:browser
npm run test:postman
```

Test integracyjny używa osobnej bazy in-memory i sprawdza XSS, odrzucenie niepoprawnych tokenów, utrzymanie zapisanej zmiany oraz osobne przywrócenie profilu, rzeczywiste nagłówki cookie oraz zapis legalnych formularzy. Test przeglądarkowy również działa na własnej bazie in-memory i losowych portach; nie zmienia danych użytkownika.

Na macOS test korzysta z zainstalowanego Google Chrome. Bez niego: `npx playwright install chromium`. Test przeglądarkowy sprawdza oba tryby, rzeczywistą zmianę DOM, żądanie z innego origin, eksport JSON, widok 390 px i cookie HTTPS. Tworzy materiały w `evidence/`; brak certyfikatu oznacza jawne pominięcie sprawdzenia HTTPS.

Test kolekcji Postmana uruchamia Newman 6.2.2 przez npx na własnej bazie in-memory. Pierwsze uruchomienie wymaga internetu. Sprawdza 29 żądań i 88 asercji dla HTTP oraz HTTPS, jeśli dostępne są certyfikaty. Runner jest zewnętrznym narzędziem i nie jest zależnością serwera. `npm run postman:generate` odtwarza kolekcję z aktualnego payloadu.

[Zgodność z kartą, ryzyko i standardy](docs/project-alignment.md) · [Materiały dowodowe](evidence/README.md)

## Losowe dane i utrzymanie skutku CSRF

Przed każdą próbą UI pokazuje nowe imię i nazwisko oraz unikalny e-mail example.test. Po zaakceptowanym żądaniu dane pozostają w bazie i w Profilu testowym. Po odrzuconej próbie wylosowane dane nie są zapisywane. T5 to legalny zapis, również pozostawiony w bazie. Osobny przycisk przywraca profil sprzed pierwszej zaakceptowanej próby; pobierz [oddzielną kolekcję ręcznego restore](postman/BAI-P7-manual-restore.postman_collection.json), jeśli chcesz wykonać tę operację w Postmanie. Główna kolekcja jej nie uruchamia.
