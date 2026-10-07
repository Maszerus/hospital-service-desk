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
  let display_name;
  do {
    display_name =
      firstNames[randomInt(firstNames.length)] + ' ' + surnames[randomInt(surnames.length)];
  } while (display_name === previous.display_name);
  const slug = display_name
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/ł/g, 'l')
    .toLowerCase()
    .replace(/\s+/g, '.');
  return { display_name, email: `${slug}.${randomUUID()}@example.test` };
}
module.exports = { generateProfile };
