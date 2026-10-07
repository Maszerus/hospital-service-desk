(() => {
  const select = (selector) => document.querySelector(selector);
  function update(state) {
    select('#live-profile-name').textContent = state.profile.display_name;
    select('#live-profile-email').textContent = state.profile.email;
    select('#restore-profile').disabled = !state.canRestore;
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
    const button = select('#restore-profile');
    button.disabled = true;
    const status = select('#profile-action-status');
    status.textContent = 'Przywracanie profilu — osobny POST z poprawnym tokenem…';
    try {
      const infoResponse = await fetch('/lab/test-info', { cache: 'no-store' });
      if (!infoResponse.ok) throw new Error('Pobranie tokenu: HTTP ' + infoResponse.status);
      const info = await infoResponse.json();
      const response = await fetch('/lab/profile-restore', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ csrfToken: info.csrfToken }),
      });
      const result = await response.json();
      if (!response.ok || !result.restored)
        throw new Error(result.error || 'Nie potwierdzono przywrócenia.');
      const state = await refresh();
      const formName = select('form[action="/profile/update"] [name="display_name"]');
      const formEmail = select('form[action="/profile/update"] [name="email"]');
      if (formName) formName.value = state.profile.display_name;
      if (formEmail) formEmail.value = state.profile.email;
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
        button.disabled = false;
      }
    }
  }
  window.profileDemo = { update, refresh };
  select('#restore-profile')?.addEventListener('click', restore);
  document.addEventListener('click', (event) => {
    if (event.target.closest('[data-show-current-profile]')) {
      const profile = select('.live-profile');
      const panel = profile?.closest('details');
      if (panel) panel.open = true;
      profile?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  });
})();
