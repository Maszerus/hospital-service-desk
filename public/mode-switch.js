document.querySelectorAll('[data-mode]').forEach((button) =>
  button.addEventListener('click', async () => {
    const mode = button.dataset.mode;
    button.disabled = true;

    try {
      const response = await fetch('/lab/mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Nie udało się zmienić trybu');

      location.reload();
    } catch (error) {
      alert('Błąd zmiany trybu: ' + error.message);
      button.disabled = false;
    }
  }),
);
