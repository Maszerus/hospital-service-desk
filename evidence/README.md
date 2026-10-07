# Dowody techniczne P7

Materiały są generowane poleceniem `npm run test:browser` na osobnej bazie in-memory i lokalnych portach:

- `before-dashboard.png` — T1: rzeczywista zmiana DOM; T3/T4: zapis losowych danych i potwierdzenie utrzymania zmiany.
- `after-dashboard.png` — T2: payload jako tekst; T3/T4: HTTP 403; T5: legalna zmiana; tabela BEFORE → AFTER.
- `mobile.png` — zrzut ekranu widoku 390 px bez przewijania całej strony w poziomie.
- `mobile-xss.png` — oba podglądy XSS w układzie mobilnym.
- `xss-exact-payload.png` — pełny payload i jego wyjaśnienie widoczne przed testem.
- `xss-visible-changes.png` — rzeczywiste podglądy przed i po wykonaniu XSS.
- `csrf-persistent-change.png` — losowe dane, rzeczywisty zapis i niezależny odczyt bez automatycznego przywrócenia.
- `xss-blocked.png` — podgląd po ochronie, payload jako tekst bez wykonania.
- `postman-results.json` — wynik uruchomienia rzeczywistej kolekcji przez Newman: żądania, asercje i błędy (bez cookie/tokenów). Wygeneruj przez `npm run test:postman`.
- `browser-results.json` — wyniki obserwacji i odpowiedzi.
- `P7-evidence-before-after.json` — plik pobrany rzeczywistym przyciskiem eksportu z aplikacji.
- `cross-origin-results.json` — formularz z drugiego portu: zmiana przed ochroną, 403 i niezmieniony profil po zabezpieczeniu. Ten sam site, różne origin.
- `https-results.json` — rzeczywiste Set-Cookie i flagi zapisane przez przeglądarkę po logowaniu HTTPS; wartość sesji usunięta. Wymaga wcześniejszego `npm run https:cert`.

Czasy w JSON są zapisane w UTC (ISO 8601). Wszystkie dane są laboratoryjne. Test T6 interfejsu po HTTP nie potwierdza flagi Secure; potwierdzenie HTTPS jest osobnym artefaktem. Materiały dokumentują konkretne testy, nie zastępują raportu 8–12 stron wymaganego kartą projektu.
