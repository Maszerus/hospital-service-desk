const htmlEntities = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  "'": '&#39;',
  '"': '&quot;',
};

function escapeHtml(value = '') {
  return String(value).replace(/[&<>'"]/g, (character) => htmlEntities[character]);
}

function codeBlock(label, value) {
  return `
    <div class="code-box">
      <b>${label}</b>
      <pre>${escapeHtml(value)}</pre>
    </div>
  `;
}

module.exports = { escapeHtml, codeBlock };
