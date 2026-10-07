function curlPost(endpoint, body) {
  return [
    `curl --request POST 'http://localhost:3000${endpoint}' \\`,
    "  --header 'Content-Type: application/json' \\",
    `  --data-raw '${JSON.stringify(body)}'`,
  ].join('\n');
}

function instructionCommands() {
  return {
    login: {
      label: 'Logowanie — zapis cookie sesji w Postmanie',
      value: curlPost('/login', { username: 'student', password: 'student123' }),
    },
    vulnerableMode: {
      label: 'Wersja podatna — HTTP 200',
      value: curlPost('/lab/mode', { mode: 'vulnerable' }),
    },
    missingToken: {
      label: 'T3 — brak tokenu: przed 200, po 403',
      value: curlPost('/lab/profile-probe', {
        display_name: 'Profil zmieniony przez T3',
        email: 't3-probe@example.test',
      }),
    },
    invalidToken: {
      label: 'T4 — błędny token: przed 200, po 403',
      value: curlPost('/lab/profile-probe', {
        display_name: 'Profil zmieniony przez T4',
        email: 't4-probe@example.test',
        csrfToken: 'INVALID-TOKEN',
      }),
    },
    secureMode: {
      label: 'Włączenie ochrony — unieważnia poprzedni token',
      value: curlPost('/lab/mode', { mode: 'secure' }),
    },
    testInfo: {
      label: 'Pobranie tokenu i nagłówków dla aktualnej sesji',
      value: "curl --request GET 'http://localhost:3000/lab/test-info'",
    },
    validToken: {
      label: 'T5 — w gotowej kolekcji zmienna jest uzupełniana automatycznie',
      value: curlPost('/lab/profile-probe', {
        display_name: 'Profil zmieniony przez T5',
        email: 't5-probe@example.test',
        csrfToken: '{{csrfToken}}',
      }),
    },
    https: {
      label: 'Terminal — uruchomienie HTTPS',
      value: ['npm run https:cert', 'npm run start:https'].join('\n'),
    },
    csrfDemo: { label: 'Terminal — druga strona localhost', value: 'npm run demo:csrf' },
    verification: {
      label: 'Sprawdzenie aplikacji i kolekcji',
      value: ['npm test', 'npm run test:browser', 'npm run test:postman'].join('\n'),
    },
  };
}

module.exports = { instructionCommands };
