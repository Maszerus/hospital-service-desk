document.querySelectorAll('[data-mode]').forEach((btn) =>
  btn.addEventListener('click', async () => {
    const mode = btn.dataset.mode;
    btn.disabled = true;
    try {
      const r = await fetch('/lab/mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode }),
      });
      const j = await r.json();
      if (!r.ok) throw new Error(j.error || 'Nie udało się zmienić trybu');
      location.reload();
    } catch (e) {
      alert('Błąd zmiany trybu: ' + e.message);
      btn.disabled = false;
    }
  }),
);
