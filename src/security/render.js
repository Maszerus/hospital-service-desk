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

module.exports = { escapeHtml };
