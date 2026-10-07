const { verify } = require('./csrf');
const xss = require('./lab-xss');

function testGuide(id, mode, candidate) {
  const secure = mode === 'secure';

  if (id === 'T1' || id === 'T2') {
    return xssGuide(id, secure);
  }

  if (id === 'T6') {
    return headersGuide();
  }

  return csrfGuide(id, secure, candidate);
}

function xssGuide(id, secure) {
  const expectedResult = secure
    ? 'HTTP 200, payload widoczny jako tekst, brak elementu img i brak wykonania onerror. Wszystkie elementy strony pozostają takie jak przed próbą.'
    : 'HTTP 200, wykonanie onerror i widoczne zmiany elementów strony. To potwierdzenie podatności, nie bezpieczeństwa.';

  return {
    template: 'guides/xss.html',
    id,
    expectedResult,
    codeExamples: {
      payload: { label: 'Dokładny payload — to cały opis zapisywany w SQLite', value: xss.payload },
      renderer: {
        label: 'Rzeczywista funkcja · app.js / renderDescription',
        value: [
          "const renderDescription=value=>currentMode==='secure'?escapeHtml(value):value;",
          '// vulnerable: aktywna jest gałąź value (surowy HTML)',
        ].join('\n'),
      },
      protection: {
        label: 'Aktywna ochrona w trybie secure',
        value: [
          'escapeHtml(value)',
          '// < staje się &lt;, > staje się &gt;',
          "// Helmet dodatkowo wysyła CSP: script-src 'self'; script-src-attr 'none'",
        ].join('\n'),
      },
    },
  };
}

function headersGuide() {
  return { template: 'guides/headers.html' };
}

function csrfGuide(id, secure, candidate) {
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

  const expectedResult =
    id === 'T5' || !secure
      ? 'HTTP 200, changed=true, persisted=true, autoRestored=false; odpowiedź zawiera before i observed. Nowy profil pozostaje zapisany.'
      : 'HTTP 403; odpowiedź „403 Forbidden - invalid CSRF token”; profil przed i po identyczny.';

  return {
    template: 'guides/csrf.html',
    id,
    goal,
    candidate,
    request,
    expectedResult,
    codeExamples: {
      verification: {
        label: 'Rzeczywista funkcja kontroli · src/security/csrf.js',
        value: verify.toString(),
      },
    },
  };
}

module.exports = { testGuide };
