const { randomInt, randomUUID } = require('node:crypto');

const firstNames = [
  'Anna',
  'Marta',
  'Joanna',
  'Katarzyna',
  'Magdalena',
  'Piotr',
  'Jan',
  'Adam',
  'Michał',
  'Tomasz',
  'Paweł',
  'Jakub',
];
const surnames = [
  'Nowak',
  'Wójcik',
  'Mazur',
  'Krawczyk',
  'Kaczmarek',
  'Zając',
  'Król',
  'Wróbel',
  'Dudek',
  'Wieczorek',
  'Lis',
  'Pawlak',
];

function generateProfile(previous = {}) {
  let displayName;
  do {
    const firstName = firstNames[randomInt(firstNames.length)];
    const surname = surnames[randomInt(surnames.length)];
    displayName = `${firstName} ${surname}`;
  } while (displayName === previous.display_name);

  const slug = displayName
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/ł/g, 'l')
    .toLowerCase()
    .replace(/\s+/g, '.');
  return { display_name: displayName, email: `${slug}.${randomUUID()}@example.test` };
}

module.exports = { generateProfile };
