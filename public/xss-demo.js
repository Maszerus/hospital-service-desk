(() => {
  if (document.getElementById('xss-proof')) return;
  const brand = document.getElementById('app-brand');
  if (brand) brand.textContent = '⚠️ HOSPITAL SERVICE DESK — XSS COMPROMISED';
  const panel = document.createElement('section');
  panel.id = 'xss-proof';
  panel.className = 'xss-proof';
  panel.innerHTML = `<h2>⚠️ XSS EXECUTED — JavaScript został wykonany</h2>
  <p><b>Co się wydarzyło?</b> Opis zgłoszenia został zapisany w bazie, a następnie wyrenderowany bez bezpiecznego kodowania. Przeglądarka potraktowała dane użytkownika jak kod i uruchomiła lokalny skrypt demonstracyjny.</p>
  <div class="proof-grid"><div><span>Typ</span><b>Stored XSS</b></div><div><span>Źródło</span><b>Opis zgłoszenia</b></div><div><span>Skutek demo</span><b>Modyfikacja DOM</b></div><div><span>Tryb</span><b>VULNERABLE</b></div></div>
  <p><b>Znaczenie bezpieczeństwa:</b> podatność XSS może pozwolić na zmianę interfejsu lub wykonywanie operacji w kontekście sesji użytkownika. W tym laboratorium demonstracja ogranicza się wyłącznie do bezpiecznej zmiany wyglądu strony.</p>`;
  const main = document.querySelector('main');
  if (main) main.prepend(panel);
})();
