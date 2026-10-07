(() => {
  const select = (selector) => document.querySelector(selector);
  const restoreButton = select('#restore-profile');
  let canRestore = !restoreButton.disabled;
  let testsRunning = false;

  function setBusy(isBusy) {
    testsRunning = isBusy;
    restoreButton.disabled = testsRunning || !canRestore;
  }

  function update(state) {
    canRestore = state.canRestore;
    select('#live-profile-name').textContent = state.profile.display_name;
    select('#live-profile-email').textContent = state.profile.email;
    restoreButton.disabled = testsRunning || !canRestore;
    select('#profile-change-note').textContent = state.canRestore
      ? 'Zmiana pozostaje zapisana w SQLite, także po odświeżeniu. Przywrócenie wymaga osobnego kliknięcia.'
      : 'Profil bez zapisanej kopii do przywrócenia. Pierwsza zaakceptowana próba zachowa dane początkowe.';
    select('#live-profile-baseline').textContent = state.initialProfile
      ? `Profil sprzed pierwszej próby: ${state.initialProfile.display_name} · ${state.initialProfile.email}`
      : 'Nie zachowano jeszcze profilu początkowego.';
  }

  async function refresh() {
    const response = await fetch('/lab/profile-state', { cache: 'no-store' });
    if (!response.ok) throw new Error('Odczyt profilu: HTTP ' + response.status);
    const state = await response.json();
    update(state);
    return state;
  }

  async function restore() {
    restoreButton.disabled = true;
    const status = select('#profile-action-status');
    status.textContent = 'Przywracanie profilu — osobny POST z poprawnym tokenem…';

    try {
      const infoResponse = await fetch('/lab/test-info', { cache: 'no-store' });
      if (!infoResponse.ok) throw new Error('Pobranie tokenu: HTTP ' + infoResponse.status);
      const testInfo = await infoResponse.json();

      const response = await fetch('/lab/profile-restore', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ csrfToken: testInfo.csrfToken }),
      });
      const result = await response.json();
      if (!response.ok || !result.restored)
        throw new Error(result.error || 'Nie potwierdzono przywrócenia.');

      const state = await refresh();
      const displayNameInput = select('form[action="/profile/update"] [name="display_name"]');
      const emailInput = select('form[action="/profile/update"] [name="email"]');
      if (displayNameInput) displayNameInput.value = state.profile.display_name;
      if (emailInput) emailInput.value = state.profile.email;

      status.textContent =
        'Profil przywrócony na Twoje żądanie: ' +
        state.profile.display_name +
        ' · ' +
        state.profile.email +
        '. Wyniki wcześniejszych testów pozostają historią wykonanych prób.';
    } catch (error) {
      status.textContent = error.message;
      try {
        await refresh();
      } catch {
        restoreButton.disabled = testsRunning || !canRestore;
      }
    }
  }

  window.profileDemo = { update, refresh, setBusy };
  restoreButton.addEventListener('click', restore);
  document.addEventListener('click', (event) => {
    if (!event.target.closest('[data-show-current-profile]')) return;

    const profile = select('.live-profile');
    const panel = profile?.closest('details');
    if (panel) panel.open = true;
    profile?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  });
})();
