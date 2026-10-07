const securityTests = require('../security/scenarios');
const { testGuide } = require('../security/scenario-guide');
const { generateProfile } = require('../security/lab-profile');

function testCards(mode, profile) {
  return securityTests
    .map(({ id, name, description, action, mode: requiredMode }) => {
      const unavailable = requiredMode && requiredMode !== mode;
      const reason =
        requiredMode === 'secure'
          ? 'Włącz ochronę, aby wykonać ten test.'
          : 'Wyłącz ochronę, aby wykonać ten atak.';
      const buttonAttributes = unavailable
        ? `disabled data-unavailable="true" aria-describedby="unavailable-${id}"`
        : '';

      return `
        <section class="test-card${unavailable ? ' test-unavailable' : ''}" id="card-${id}">
          <div class="test-head">
            <div>
              <span class="test-id">${id}</span>
              <h2>${name}</h2>
            </div>
            <button type="button" class="run-test" data-test="${id}" ${buttonAttributes}>${action}</button>
          </div>
          ${unavailable ? `<p class="unavailable-reason" id="unavailable-${id}">${reason}</p>` : ''}
          <details class="test-details">
            <summary>Szczegóły testu / ataku</summary>
            <p>${description}</p>
            ${testGuide(id, requiredMode || mode, generateProfile(profile))}
          </details>
          <div class="test-result" aria-live="polite" id="result-${id}"></div>
        </section>
      `;
    })
    .join('');
}

module.exports = { testCards };
