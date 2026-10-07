const securityTests = require('./scenarios');
const { testGuide } = require('./scenario-guide');
const { generateProfile } = require('./lab-profile');

function testCards(mode, profile) {
  return securityTests.map((scenario) => {
    const unavailable = !!scenario.mode && scenario.mode !== mode;
    const reason =
      scenario.mode === 'secure'
        ? 'Włącz ochronę, aby wykonać ten test.'
        : 'Wyłącz ochronę, aby wykonać ten atak.';

    return {
      ...scenario,
      unavailable,
      reason,
      guide: testGuide(scenario.id, scenario.mode || mode, generateProfile(profile)),
    };
  });
}

module.exports = { testCards };
