(() => {
  const username = document.querySelector('input[name="username"]');
  const storageKey = 'hsd-username';

  try {
    if (username) username.value = localStorage.getItem(storageKey) || '';
  } catch {}

  username?.form.addEventListener('submit', () => {
    try {
      localStorage.setItem(storageKey, username.value.trim());
    } catch {}
  });

  document.querySelector('form[action="/logout"]')?.addEventListener('submit', () => {
    try {
      localStorage.removeItem(storageKey);
      sessionStorage.removeItem('hsd-evidence');
    } catch {}
  });
})();
