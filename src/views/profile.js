const { escapeHtml } = require('../security/render');

function profilePanel(state) {
  const { profile, initialProfile, canRestore } = state;
  const baseline = initialProfile
    ? `Profil sprzed pierwszej próby: ${escapeHtml(initialProfile.display_name)} · ${escapeHtml(initialProfile.email)}`
    : 'Nie zachowano jeszcze profilu początkowego.';
  const changeNote = canRestore
    ? 'Zapis po demonstracji pozostaje w bazie. Przywrócenie danych jest osobną operacją.'
    : 'Po zaakceptowanym teście zobaczysz tutaj nowe dane. Nic nie zostanie automatycznie cofnięte.';

  return `
    <section class="live-profile" aria-label="Aktualny profil w bazie">
      <div>
        <span class="eyebrow">AKTUALNY PROFIL · ODCZYT Z SQLITE</span>
        <strong id="live-profile-name">${escapeHtml(profile.display_name)}</strong>
        <span id="live-profile-email">${escapeHtml(profile.email)}</span>
        <small id="live-profile-baseline">${baseline}</small>
        <p id="profile-change-note">${changeNote}</p>
      </div>
      <div>
        <button type="button" class="secondary" id="restore-profile" ${canRestore ? '' : 'disabled'}>Przywróć profil sprzed pierwszej próby</button>
        <a href="/profile">Otwórz profil testowy →</a>
        <p id="profile-action-status" role="status"></p>
      </div>
    </section>
  `;
}

module.exports = { profilePanel };
