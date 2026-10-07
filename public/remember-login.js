(() => {
  const usernameInput = document.querySelector('input[name="username"]');
  const storageKey = 'hsd-username';

  try {
    if (usernameInput) usernameInput.value = localStorage.getItem(storageKey) || '';
  } catch {}

  usernameInput?.form.addEventListener('submit', () => {
    try {
      localStorage.setItem(storageKey, usernameInput.value.trim());
    } catch {}
  });

  document.querySelector('form[action="/logout"]')?.addEventListener('submit', () => {
    try {
      localStorage.removeItem(storageKey);
      sessionStorage.removeItem('hsd-evidence');
    } catch {}
  });
})();
