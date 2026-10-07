const fs=require('node:fs');
const {payload}=require('../src/security/lab-xss');
const schema='https://schema.getpostman.com/json/collection/v2.1.0/collection.json';
const event=code=>({listen:'test',script:{type:'text/javascript',exec:code.split('\n')}});
function item(name,method,path,body,description,code){
 const request={method,header:body===undefined?[]:[{key:'Content-Type',value:'application/json'}],url:'{{baseUrl}}'+path,description};
 if(body!==undefined)request.body={mode:'raw',raw:JSON.stringify(body,null,2),options:{raw:{language:'json'}}};
 return {name,request,event:[event(code)],protocolProfileBehavior:{followRedirects:false}};
}
const success="pm.test('HTTP 200',()=>pm.response.to.have.status(200));";
const infoScript=mode=>`${success}
const j=pm.response.json();
pm.test('Aktywny tryb: ${mode}',()=>pm.expect(j.mode).to.eql('${mode}'));
pm.collectionVariables.set('csrfToken',j.csrfToken);
pm.test('Token tej sesji dostępny',()=>pm.expect(j.csrfToken).to.be.a('string').and.not.empty);`;
const stateScript=save=>`${success}
const j=pm.response.json();
${save?"pm.collectionVariables.set('profileBefore',JSON.stringify(j.profile));pm.collectionVariables.set('profileExpected',JSON.stringify(j.profile));":"pm.test('Aktualny profil zgodny z ostatnim zaakceptowanym zapisem',()=>pm.expect(j.profile).to.deep.eql(JSON.parse(pm.collectionVariables.get('profileExpected'))));"}`;
const acceptedScript=`${success}
const j=pm.response.json();
const sent=JSON.parse(pm.variables.replaceIn(pm.request.body.raw));
pm.test('UPDATE rzeczywiście zmienił dane',()=>pm.expect(j.changed).to.eql(true));
pm.test('Zapis pozostaje w bazie',()=>pm.expect(j.persisted).to.eql(true));
pm.test('Bez automatycznego restore',()=>pm.expect(j.autoRestored).to.eql(false));
pm.test('Zapisane dane zgodne z wylosowanymi',()=>pm.expect(j.observed).to.deep.eql({display_name:sent.display_name,email:sent.email}));
pm.collectionVariables.set('profileExpected',JSON.stringify(j.observed));`;
const candidateItem=()=>item('Wylosuj dane następnej próby','GET','/lab/profile-candidate',undefined,'Generuje nowe fikcyjne imię i nazwisko oraz unikalny e-mail example.test. Nie zmienia profilu. Skrypt ustawia displayName i email.',`${success}\nconst j=pm.response.json();\npm.collectionVariables.set('displayName',j.display_name);\npm.collectionVariables.set('email',j.email);\npm.test('Fikcyjna domena',()=>pm.expect(j.email).to.match(/@example\\.test$/));`);
const rejectedScript="pm.test('HTTP 403 — błędny lub brak tokenu',()=>pm.response.to.have.status(403));\npm.test('Jawny komunikat odrzucenia',()=>pm.expect(pm.response.text()).to.include('invalid CSRF token'));";
function headersScript(secure){return `${infoScript(secure?'secure':'vulnerable')}
pm.test('CSP: ${secure?'aktywne':'brak'}',()=>pm.expect(!!pm.response.headers.get('Content-Security-Policy')).to.eql(${secure}));
pm.test('SameSite: ${secure?'strict':'lax'}',()=>pm.expect(j.cookie.sameSite).to.eql('${secure?'strict':'lax'}'));
pm.test('HttpOnly konfiguracja',()=>pm.expect(j.cookie.httpOnly).to.eql(true));
const setCookie=pm.response.headers.get('Set-Cookie')||'';
pm.test('Rzeczywiste Set-Cookie: HttpOnly',()=>pm.expect(setCookie).to.match(/;\\s*HttpOnly/i));
pm.test('Rzeczywiste Set-Cookie: SameSite',()=>pm.expect(setCookie).to.match(/SameSite=${secure?'Strict':'Lax'}/i));
const https=pm.variables.replaceIn('{{baseUrl}}').startsWith('https:');
const expectSecure=${secure}&&https;
pm.test('Secure zgodne z trybem i protokołem',()=>pm.expect(j.cookie.secure).to.eql(expectSecure));
pm.test('Set-Cookie: rzeczywista flaga Secure',()=>pm.expect(/;\\s*Secure(?:;|$)/i.test(setCookie)).to.eql(expectSecure));
${secure?"pm.test('nosniff',()=>pm.expect(pm.response.headers.get('X-Content-Type-Options')).to.eql('nosniff'));\npm.test('SAMEORIGIN',()=>pm.expect(pm.response.headers.get('X-Frame-Options')).to.eql('SAMEORIGIN'));":''}
if(${secure}&&!https)console.warn('HTTP: test Secure na true nie został wykonany. Powtórz kolekcję na https://localhost:3443.');`}
function folder(secure){const mode=secure?'secure':'vulnerable',xssId=secure?'T2':'T1';return {name:secure?'02 AFTER — zabezpieczenia i re-test':'01 BEFORE — wersja podatna',description:'Wykonuj żądania w kolejności. Test XSS tutaj sprawdza zapis i HTML; wykonanie JavaScript sprawdź w laboratorium w przeglądarce.',item:[
 item('01 Włącz '+mode,'POST','/lab/mode',{mode},'Zmienia globalny tryb procesu. Poprzedni token CSRF zostaje unieważniony.',`${success}\npm.test('Tryb przełączony',()=>pm.expect(pm.response.json().mode).to.eql('${mode}'));`),
 item('02 Odczytaj profil BEFORE','GET','/lab/profile-state',undefined,'Zapisuje profil początkowy jako zmienną profileBefore.',stateScript(true)),
 item('03 Pobierz świeży token tej sesji','GET','/lab/test-info',undefined,'Po każdej zmianie trybu trzeba pobrać nowy token. Skrypt uzupełnia csrfToken.',infoScript(mode)),
 item('04 '+xssId+' — odczytaj dokładny payload i jego instrukcje','GET','/lab/xss-info',undefined,'Odpowiedź zawiera payload, dekodowany script, selektory zmian, aktywne renderowanie i rekord SQLite.',`${success}\nconst j=pm.response.json();\npm.collectionVariables.set('xssPayload',j.payload);\npm.test('Payload zawiera jawny kod onerror',()=>pm.expect(j.payload).to.include('onerror='));`),
 item('05 '+xssId+' — zapisz ten opis w SQLite','POST','/lab/xss-probe',{description:payload},'Dokładny payload jest widoczny w Body. Serwer odpowiada odczytanym rekordem, nie tylko deklaracją sukcesu.',`${success}\nconst j=pm.response.json();\npm.test('Payload zapisany',()=>pm.expect(j.stored).to.eql(true));\npm.test('Odczyt zgodny z payloadem',()=>pm.expect(j.storage.record.description).to.eql(pm.collectionVariables.get('xssPayload')));`),
 item('06 '+xssId+' — odbierz HTML po odczycie opisu','GET','/lab/xss-frame',undefined,'Sprawdź odpowiedź HTML w Body → Raw. Postman nie jest testem wykonania JavaScript w przeglądarce. Zaloguj się osobno w przeglądarce i uruchom T1/T2, aby zobaczyć rzeczywiste zmiany DOM.',`${success}\nconst html=pm.response.text();\npm.test('${secure?'Opis zakodowany jako tekst':'Opis wstawiony jako aktywny HTML'}',()=>{pm.expect(html).to.include('${secure?'&lt;img':'<img'}');${secure?"pm.expect(html).not.to.include('<img');":''}});`),
 candidateItem(),
 item('07 T3 — POST bez tokenu','POST','/lab/profile-probe',{display_name:'{{displayName}}',email:'{{email}}'},secure?'Oczekiwane HTTP 403, brak zapisu.':'Oczekiwane HTTP 200, before → observed; zmiana pozostaje w bazie. To potwierdzenie braku walidacji tokenu.',secure?rejectedScript:acceptedScript),
 ...(secure?[item('Sprawdź brak zmiany po T3','GET','/lab/profile-state',undefined,'Profil musi być identyczny jak przed odrzuconym żądaniem.',stateScript(false))]:[]),
 candidateItem(),
 item('08 T4 — POST z błędnym tokenem','POST','/lab/profile-probe',{display_name:'{{displayName}}',email:'{{email}}',csrfToken:'INVALID-TOKEN'},secure?'Oczekiwane HTTP 403.':'Oczekiwane HTTP 200 mimo błędnego tokenu.',secure?rejectedScript:acceptedScript),
 ...(secure?[item('Sprawdź brak zmiany po T4','GET','/lab/profile-state',undefined,'Profil musi być identyczny jak przed odrzuconym żądaniem.',stateScript(false)),candidateItem(),item('09 T5 — POST z poprawnym tokenem','POST','/lab/profile-probe',{display_name:'{{displayName}}',email:'{{email}}',csrfToken:'{{csrfToken}}'},'Skrypt kroku 03 pobrał prawidłowy token po przełączeniu trybu. Oczekiwane 200; nowe dane pozostają zapisane.',acceptedScript)]:[]),
 item('10 Odczytaj profil AFTER','GET','/lab/profile-state',undefined,'Niezależny odczyt profilu; oczekiwane dane z ostatniego zaakceptowanego zapisu. Żaden test nie przywraca danych automatycznie.',stateScript(false)),
 item('11 T6 — rzeczywiste nagłówki i Set-Cookie','GET','/lab/test-info',undefined,'Sprawdź Headers: Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, Set-Cookie. Secure=true sprawdzamy wyłącznie dla HTTPS w trybie secure.',headersScript(secure)),
 ]};}
const collection={info:{name:'BAI P7 — Browser Hardening — BEFORE i AFTER',description:'Własna aplikacja localhost. Uruchom całość w kolejności: logowanie → BEFORE → AFTER. Postman zapisuje connect.sid w cookie jar. Nie mieszaj localhost z 127.0.0.1. XSS: Postman sprawdza zapis/HTML, a przeglądarka wykonanie JS. HTTP nie potwierdza Secure=true. Szczegółowa instrukcja: /instructions i docs/postman.md.',schema},variable:[{key:'baseUrl',value:'http://localhost:3000',type:'string'},{key:'csrfToken',value:'',type:'string'},{key:'profileBefore',value:'',type:'string'},{key:'xssPayload',value:'',type:'string'},{key:'displayName',value:'',type:'string'},{key:'email',value:'',type:'string'},{key:'profileExpected',value:'',type:'string'}],item:[{name:'00 Start — logowanie i cookie sesji',item:[item('Zaloguj konto laboratoryjne','POST','/login',{username:'student',password:'student123'},'Oczekiwane 302 i Set-Cookie connect.sid. Automatyczne przekierowania wyłączone dla tego żądania. Cookie jar pozostaw włączony.',"pm.test('Logowanie: HTTP 302',()=>pm.response.to.have.status(302));\npm.test('Set-Cookie sesji',()=>pm.expect(pm.response.headers.get('Set-Cookie')).to.include('connect.sid='));\npm.test('Przekierowanie do laboratorium',()=>pm.expect(pm.response.headers.get('Location')).to.eql('/security-tests'));" )]},folder(false),folder(true)]};
for(const folder of collection.item)folder.item.forEach((request,index)=>{request.name=String(index+1).padStart(2,'0')+' '+request.name.replace(/^\d+\s*/,'');});
fs.writeFileSync('postman/BAI-P7.postman_collection.json',JSON.stringify(collection,null,2)+'\n');
const restoreCollection={info:{name:'BAI P7 — opcjonalne ręczne przywrócenie profilu',description:'Uruchom WYŁĄCZNIE na własne żądanie, z tym samym cookie jar po demonstracji. Główna kolekcja nigdy nie uruchamia restore. Kopia profilu sprzed pierwszej próby jest przechowywana w SQLite.',schema},variable:[{key:'baseUrl',value:'http://localhost:3000',type:'string'},{key:'csrfToken',value:'',type:'string'},{key:'initialProfile',value:'',type:'string'}],item:[
 item('01 Odczytaj zachowany profil początkowy','GET','/lab/profile-state',undefined,'Kopia pochodzi z pierwszej zaakceptowanej próby i nie jest nadpisywana przy kolejnych atakach.',`${success}\nconst j=pm.response.json();\npm.test('Dostępna kopia do przywrócenia',()=>pm.expect(j.initialProfile).not.to.eql(null));\npm.collectionVariables.set('initialProfile',JSON.stringify(j.initialProfile));`),
 item('02 Pobierz token do legalnego przywrócenia','GET','/lab/test-info',undefined,'Restore wymaga poprawnego tokenu w obu trybach.',`${success}\npm.collectionVariables.set('csrfToken',pm.response.json().csrfToken);`),
 item('03 Przywróć profil — osobna operacja','POST','/lab/profile-restore',{csrfToken:'{{csrfToken}}'},'Oczekiwane 200 i restored=true. Po przywróceniu kopia jest usuwana.',`${success}\nconst j=pm.response.json();\npm.test('Ręczne przywrócenie',()=>pm.expect(j.manual&&j.restored).to.eql(true));\npm.test('Dane zgodne z kopią',()=>pm.expect(j.restoredState).to.deep.eql(JSON.parse(pm.collectionVariables.get('initialProfile'))));`),
 item('04 Potwierdź przywrócony profil niezależnym GET','GET','/lab/profile-state',undefined,'Profil powinien być pierwotny, kopia została zużyta.',`${success}\nconst j=pm.response.json();\npm.test('Aktualny profil zgodny z kopią',()=>pm.expect(j.profile).to.deep.eql(JSON.parse(pm.collectionVariables.get('initialProfile'))));\npm.test('Kopia wyczyszczona',()=>pm.expect(j.canRestore).to.eql(false));`)
]};
fs.writeFileSync('postman/BAI-P7-manual-restore.postman_collection.json',JSON.stringify(restoreCollection,null,2)+'\n');
fs.writeFileSync('postman/localhost.postman_environment.json',JSON.stringify({name:'BAI P7 — HTTP localhost',values:[{key:'baseUrl',value:'http://localhost:3000',type:'default',enabled:true}],_postman_variable_scope:'environment'},null,2)+'\n');
fs.writeFileSync('postman/localhost-https.postman_environment.json',JSON.stringify({name:'BAI P7 — HTTPS localhost',values:[{key:'baseUrl',value:'https://localhost:3443',type:'default',enabled:true}],_postman_variable_scope:'environment'},null,2)+'\n');
console.log('Wygenerowano kolekcję oraz środowiska HTTP/HTTPS.');
