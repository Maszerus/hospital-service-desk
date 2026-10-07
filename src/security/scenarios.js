const securityTests = [
  {
    id: 'T1',
    name: 'Stored XSS — atak',
    description: 'Czy kontrolowany payload zostanie wykonany jako JavaScript?',
    action: 'Wykonaj atak',
    mode: 'vulnerable',
  },
  {
    id: 'T2',
    name: 'Stored XSS — test ochrony',
    description: 'Czy ochrona zatrzyma wykonanie tego samego payloadu XSS?',
    action: 'Wykonaj test',
    mode: 'secure',
  },
  {
    id: 'T3',
    name: 'CSRF bez tokenu — atak',
    description: 'Czy serwer zaakceptuje zmianę profilu bez tokenu CSRF?',
    action: 'Wykonaj atak',
  },
  {
    id: 'T4',
    name: 'CSRF z błędnym tokenem — atak',
    description: 'Czy serwer zaakceptuje zmianę profilu z błędnym tokenem CSRF?',
    action: 'Wykonaj atak',
  },
  {
    id: 'T5',
    name: 'CSRF z poprawnym tokenem — test',
    description: 'Czy legalne żądanie z poprawnym tokenem pozwala zapisać profil?',
    action: 'Wykonaj test',
  },
  {
    id: 'T6',
    name: 'Nagłówki bezpieczeństwa i cookies — test',
    description: 'Jakie nagłówki bezpieczeństwa i ustawienia sesji są aktywne?',
    action: 'Wykonaj test',
  },
];

module.exports = securityTests;
