const $ = selector => document.querySelector(selector);
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const revision='P7-persistent-profile-v3';
let info, busy = false, evidence = {};
try { const previous=JSON.parse(sessionStorage.getItem('hsd-evidence') || '{}'); if(previous._revision===revision)evidence=previous; } catch {}

async function request(url, options) {
 const response = await fetch(url, options);
 if (!response.ok) throw new Error(`HTTP ${response.status}: ${await response.text()}`);
 return response.json();
}
async function getInfo() { info = await request('/lab/test-info', {cache:'no-store'}); if(info.mode!==document.body.dataset.labMode)throw new Error('Tryb serwera zmieniono na '+info.mode+' (np. w Postmanie). Odśwież stronę, żeby uruchomić właściwy scenariusz.'); return info; }
function codeBlock(label, value) { return `<div class="code-box"><b>${esc(label)}</b><pre>${esc(value)}</pre></div>`; }
function compare() {
 const labels = {XSS:'XSS · wykonanie kodu',T3:'CSRF · brak tokenu',T4:'CSRF · błędny token',T5:'Legalna zmiana · poprawny token',T6:'CSP i cookie sesji'};
 $('#comparison-results').innerHTML = `<div class="table-scroll"><table><thead><tr><th>Scenariusz</th><th>Przed ochroną</th><th>Po zabezpieczeniu</th></tr></thead><tbody>${Object.entries(labels).map(([key,label]) => `<tr><th>${label}</th>${['vulnerable','secure'].map(mode => `<td>${evidence[mode]?.[key] ? esc(evidence[mode][key].summary) : '<span class="muted">Nie wykonano</span>'}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
}
function save(id, data) {
 const key = id==='T1'||id==='T2' ? 'XSS' : id;
 evidence._revision=revision;
 evidence[info.mode] ??= {};
 // Historia zawiera dane i obserwacje, bez tokenu CSRF i cookie sesji.
 const {visual, ...result} = data;
 evidence[info.mode][key] = {...result,id,mode:info.mode,timestamp:new Date().toISOString()};
 try { sessionStorage.setItem('hsd-evidence',JSON.stringify(evidence)); } catch {}
 compare();
}
function render(id, data) {
 const el = $(`#result-${id}`);
 el.querySelector('.running')?.remove();
 const preview = el.querySelector('.preview');
 const outcome = document.createElement('div');
 outcome.className = 'outcome';
 outcome.innerHTML = `<h3>Rzeczywisty wynik tego uruchomienia</h3><div class="result-banner ${data.pass ? (info.mode==='vulnerable'?'exposed':'pass') : 'fail'}"><b>${data.pass?'✓ Scenariusz potwierdzony':'✕ Wynik niezgodny'}</b><span>${esc(data.summary)}</span></div>${data.visual||''}`;
 el.insertBefore(outcome, preview || el.firstChild);
 el.insertAdjacentHTML('beforeend', `<div class="test-explanation"><p class="interpretation">${esc(data.why)}</p><h3>Dokumentacja tego uruchomienia</h3><p class="muted">Żądanie i odpowiedź poniżej pochodzą z tej próby. Cookie i poprawny token sesji pomijamy w eksporcie; Postman pobiera je po swoim logowaniu.</p><div class="detail-grid">${codeBlock('Wysłane żądanie / opis',data.request)}${codeBlock('Odpowiedź HTTP / odczytana obserwacja',data.response)}</div><p class="muted">Czas próby: ${esc(new Date().toLocaleString('pl-PL'))} · tryb ${esc(info.mode)}</p></div>`);
 save(id,data);
 return data.pass;
}
function restoreMain() {
 $('#app-header').classList.remove('xss-header');
 $('#xss-page-impact').hidden = true;
 $('#xss-page-impact').textContent = '';
 $('#xss-reset-area').hidden = true;
}
$('#reset-xss')?.addEventListener('click', restoreMain);
function mainSnapshot() {
 return {headerClass:$('#app-header').className,bannerVisible:!$('#xss-page-impact').hidden,bannerText:$('#xss-page-impact').textContent};
}
function frameSnapshot(frame, changes) {
 const doc = frame.contentDocument;
 if (!doc?.querySelector('#payload')) throw new Error('Brak oczekiwanej strony podglądu; sesja mogła wygasnąć.');
 return Object.fromEntries(changes.map(change => [change.selector,change.selector==='body'?doc.body.className:doc.querySelector(change.selector)?.textContent]));
}
function fitFrame(frame) { if(frame.contentDocument?.body)frame.style.height=Math.ceil(frame.contentDocument.body.getBoundingClientRect().height)+24+'px'; }
async function loadFrame(frame, url) {
 await new Promise((resolve,reject) => {
  const timeout = setTimeout(() => reject(new Error('Podgląd nie załadował się w ciągu 8 sekund.')),8000);
  frame.onload = () => { clearTimeout(timeout); fitFrame(frame); resolve(); };
  frame.src = url;
 });
}
async function xss(id) {
 const i = await getInfo();
 const spec = await request('/lab/xss-info');
 restoreMain();
 const beforeMain = mainSnapshot();
 const storedResponse = await fetch('/lab/xss-probe',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({description:spec.payload})});
 const stored = await storedResponse.json();
 if (!storedResponse.ok || stored.payload!==spec.payload) throw new Error('Serwer nie potwierdził zapisu dokładnie tego payloadu.');
 const htmlResponse=await fetch(stored.frameUrl,{cache:'no-store'});
 const rawHtml=await htmlResponse.text();
 if(htmlResponse.status!==200)throw new Error('Odczyt opisu HTML: HTTP '+htmlResponse.status);
 const el = $(`#result-${id}`);
 el.innerHTML = '<p class="running">Opis zapisany i odczytany z SQLite. Ładowanie strony przed i po wstawieniu opisu…</p><div class="preview paired-preview"><section><h3>PRZED · bez wstawionego payloadu</h3><iframe data-frame="before" title="Strona przed wstawieniem payloadu" class="probe-frame"></iframe></section><section><h3>PO · opis z bazy wstawiony do HTML</h3><iframe data-frame="after" title="Strona po odczycie zapisanego payloadu" class="probe-frame"></iframe></section></div>';
 const beforeFrame = el.querySelector('[data-frame=before]');
 const frame = el.querySelector('[data-frame=after]');
 let executed = false;
 const handler = event => {
  if(event.source===frame.contentWindow && event.origin===location.origin && event.data==='XSS_EXECUTED') executed=true;
 };
 window.addEventListener('message',handler);
 try {
  await loadFrame(beforeFrame,spec.baselineUrl);
  const before = frameSnapshot(beforeFrame,spec.changes);
  await loadFrame(frame,stored.frameUrl+'?ts='+Date.now());
  await new Promise(resolve=>setTimeout(resolve,400));
  const observed = frameSnapshot(frame,spec.changes);
  const afterMain = mainSnapshot();
  const doc = frame.contentDocument;
  fitFrame(frame);
  const textOnly = doc.querySelector('#payload').textContent===stored.payload && !doc.querySelector('#payload img');
  const secure = i.mode==='secure';
  const changesMatch = spec.changes.every(change => observed[change.selector]===(secure?before[change.selector]:change.after));
  const mainMatch = secure ? JSON.stringify(beforeMain)===JSON.stringify(afterMain) : afterMain.headerClass.includes('xss-header') && afterMain.bannerVisible;
  const pass = stored.stored && changesMatch && mainMatch && (secure ? !executed&&textOnly : executed);
  $('#xss-reset-area').hidden = !executed;
  const rows = spec.changes.map(change => ({element:change.label,selector:change.selector,before:before[change.selector],observed:observed[change.selector]}));
  rows.push({element:'Kolor głównego nagłówka aplikacji',selector:'parent #app-header.className',before:beforeMain.headerClass||'(bez klasy ataku)',observed:afterMain.headerClass||'(bez klasy ataku)'});
  rows.push({element:'Komunikat na głównej stronie',selector:'parent #xss-page-impact',before:beforeMain.bannerVisible?beforeMain.bannerText:'Ukryty',observed:afterMain.bannerVisible?afterMain.bannerText:'Ukryty'});
  const visual = `<div class="trace"><h3>Skąd pochodzi wykonany kod?</h3><ol><li><b>Wysłano:</b> POST /lab/xss-probe, pole description (dokładny payload z instrukcji powyżej).</li><li><b>Serwer zapisał i odczytał:</b> SQLite → tabela <code>${esc(stored.storage.table)}</code> → user_id=${esc(stored.storage.record.user_id)}. Odczytany opis jest identyczny z wysłanym: <b>${stored.payload===spec.payload?'TAK':'NIE'}</b>.</li><li><b>Przeglądarka dostała:</b> GET /lab/xss-frame, HTTP ${htmlResponse.status}. Aktywne renderowanie: <code>${esc(spec.activeRenderer)}</code>.</li><li><b>Zaobserwowano:</b> wykonanie onerror: <b>${executed?'TAK':'NIE'}</b>; payload jako tekst: <b>${textOnly?'TAK':'NIE'}</b>.</li></ol></div><h3>Rzeczywiste zmiany odczytane z elementów strony</h3><div class="table-scroll"><table class="dom-observations"><thead><tr><th>Element / selektor</th><th>Przed wstawieniem opisu</th><th>Po wstawieniu opisu</th></tr></thead><tbody>${rows.map(row=>`<tr class="${row.before!==row.observed?'changed-row':''}"><th>${esc(row.element)}<small>${esc(row.selector)}</small></th><td>${esc(row.before)}</td><td>${esc(row.observed)}</td></tr>`).join('')}</tbody></table></div><p class="expected"><b>Zmiana interfejsu głównej strony:</b> ${secure?'Nie wystąpiła. Nagłówek i komunikat pozostały bez zmian.':'Nagłówek na górze strony jest teraz pomarańczowy. Bezpośrednio pod nagłówkiem pojawił się komunikat wstawiony przez payload.'} Podglądy poniżej pokazują obie wersje tej samej strony demo.</p>`;
  return render(id,{pass,summary:executed?'Podatność potwierdzona — kod z opisu zmienił 5 elementów podglądu i 2 elementy głównej strony.':textOnly?'Atak zatrzymany — payload jest tekstem; 7 obserwowanych elementów bez zmian.':'Nie potwierdzono oczekiwanego skutku.',visual,observations:rows,storage:stored.storage,javascriptExecuted:executed,renderedAsText:textOnly,why:secure?'Znaczniki opisu zakodowano jako tekst. Nie powstał element img z onerror. CSP jest dodatkową warstwą blokującą kod inline.':'Kod pochodzi z atrybutu onerror w opisie zapisanym w SQLite. Błąd ładowania obrazu uruchomił JavaScript. Zmiany DOM odczytaliśmy z obu dokumentów; niczego nie uznajemy na podstawie samego napisu „atak”.',request:`POST /lab/xss-probe\nContent-Type: application/json\n\n${JSON.stringify({description:spec.payload},null,2)}\n\nGET /lab/xss-frame`,response:JSON.stringify({postStatus:storedResponse.status,getHtmlStatus:htmlResponse.status,htmlContainsRawImage:rawHtml.includes('<img'),stored:stored.stored,storage:stored.storage,javascriptExecuted:executed,renderedAsText:textOnly,domObservations:rows},null,2)});
 } finally { window.removeEventListener('message',handler); }
}
function stateBox(label,state) {
 return `<div><span>${esc(label)}</span><strong>${esc(state?.display_name??'Brak odczytu')}</strong><small>${esc(state?.email??'')}</small></div>`;
}
function showCandidate(id,candidate) {
 const preview=$(`#csrf-request-${id}`);
 preview.dataset.candidate=JSON.stringify(candidate);
 const body={...candidate};
 if(id==='T4')body.csrfToken='INVALID-TOKEN';
 if(id==='T5')body.csrfToken='{{csrfToken}}';
 preview.textContent='POST /lab/profile-probe\nContent-Type: application/json\nCookie: connect.sid=<cookie z logowania>\n\n'+JSON.stringify(body,null,2);
}
async function csrf(id,kind) {
 const i=await getInfo();
 const before=(await request('/lab/profile-state')).profile;
 let candidate=JSON.parse($(`#csrf-request-${id}`).dataset.candidate);
 if(candidate.display_name===before.display_name){candidate=await request('/lab/profile-candidate');showCandidate(id,candidate);}
 const body={...candidate};
 if(kind==='bad')body.csrfToken='INVALID-TOKEN';
 if(kind==='good')body.csrfToken=i.csrfToken;
 const r=await fetch('/lab/profile-probe',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
 const raw=await r.text();let j={};try{j=JSON.parse(raw);}catch{}
 const state=await request('/lab/profile-state');const after=state.profile;
 window.profileDemo.update(state);
 const expected=kind==='good'||i.mode==='vulnerable';const accepted=r.ok;
 const same=JSON.stringify(before)===JSON.stringify(after);
 const matches=after.display_name===candidate.display_name&&after.email===candidate.email;
 const valid=accepted?j.changed===true&&j.persisted===true&&j.autoRestored===false&&matches:r.status===403&&same;
 const safeBody={...body,...(kind==='good'?{csrfToken:'{{csrfToken}} — pobrany z /lab/test-info w tej sesji'}:{})};
 const visual=accepted?`<div class="state-diff">${stateBox('PRZED ŻĄDANIEM · SELECT',j.before)}<span class="arrow">→</span>${stateBox('PO UPDATE · SELECT',j.observed)}<span class="arrow">→</span>${stateBox('AKTUALNY PROFIL · OSOBNY GET',after)}</div><p class="expected"><b>HTTP ${r.status}.</b> Dane po ataku pozostają w bazie. Niezależny GET potwierdza wysłane imię, nazwisko i e-mail: <b>${matches?'TAK':'NIE'}</b>. Automatyczne przywrócenie: <b>NIE</b>.</p><div class="download-row"><button type="button" class="secondary" data-show-current-profile>Zobacz aktualny profil na tej stronie</button><a class="primary-link" href="/profile" target="_blank" rel="noopener">Otwórz zapisany profil w nowej karcie →</a></div><p class="muted">Przywrócenie jest opcjonalne: osobny przycisk w panelu aktualnego profilu przywraca dane sprzed pierwszej zaakceptowanej próby.</p>`:`<div class="blocked-effect"><b>HTTP ${r.status} · ${esc(raw)}</b><p>Token został odrzucony. Wylosowane dane ${esc(candidate.display_name)} · ${esc(candidate.email)} nie zostały zapisane.</p></div><div class="state-diff">${stateBox('GET PRZED ŻĄDANIEM',before)}<span class="arrow">→</span>${stateBox('GET PO ODRZUCENIU',after)}</div><p class="expected"><b>Profil bez zmian:</b> ${same?'TAK':'NIE'}</p>`;
 const result=render(id,{pass:accepted===expected&&valid,summary:accepted?`${kind==='good'?'Legalny zapis':'Atak zaakceptowany'} — ${after.display_name} · ${after.email}; zmiana pozostaje w profilu.`:`Żądanie odrzucone — HTTP ${r.status}; profil ${same?'bez zmian':'ZMIENIONY'}.`,visual,before,after,candidate,httpStatus:r.status,changed:j.changed??false,persisted:j.persisted??false,autoRestored:j.autoRestored??false,observed:j.observed??null,why:kind==='good'?'Poprawny token dopuścił legalny zapis. Dane pozostają w SQLite do kolejnego zapisu lub ręcznego przywrócenia.':accepted?'Żądanie bez poprawnego tokenu zmieniło dane użytkownika. Wylosowany profil pozostaje zapisany i jest widoczny w zakładce Profil testowy, także po odświeżeniu.':'HTTP 403 potwierdza odrzucenie żądania. Odczyty przed i po potwierdzają brak zmiany danych.',request:`GET /lab/profile-state\nPOST /lab/profile-probe\nContent-Type: application/json\nCookie: [sesja po logowaniu]\n\n${JSON.stringify(safeBody,null,2)}\n\nGET /lab/profile-state`,response:`HTTP ${r.status}\n${raw}\n\nNiezależne odczyty profilu:\nbefore=${JSON.stringify(before)}\nafter=${JSON.stringify(after)}\nunchanged=${same}\nmatchesSentData=${matches}`});
 try{showCandidate(id,await request('/lab/profile-candidate'));}catch(error){$(`#csrf-request-${id}`).textContent+='\n\nNie udało się przygotować kolejnych danych: '+error.message;}
 return result;
}
async function t6() {
 const i = await getInfo();
 const secure = i.mode==='secure';
 const headersMatch = secure ? !!i.headers.csp&&i.headers.xContentType==='nosniff'&&!!i.headers.xFrame : !i.headers.csp;
 const pass = headersMatch&&i.cookie.httpOnly===true&&i.cookie.sameSite===(secure?'strict':'lax')&&i.cookie.secure===(secure&&location.protocol==='https:');
 const https = location.protocol==='https:';
 return render('T6',{pass,summary:`CSP ${i.headers.csp?'aktywna':'wyłączona'} · SameSite=${i.cookie.sameSite} · Secure=${i.cookie.secure}${secure&&!https?' · hardening HTTPS jeszcze niepotwierdzony':''}`,visual:`<div class="lab-grid"><div><span>CSP</span><b>${i.headers.csp?'Włączona':'Brak ochrony'}</b></div><div><span>HttpOnly</span><b>${i.cookie.httpOnly}</b></div><div><span>SameSite</span><b>${esc(i.cookie.sameSite)}</b></div><div><span>Secure</span><b>${i.cookie.secure?'Aktywne':https?'Wyłączone w tym trybie':'Nieaktywne · HTTP'}</b></div></div>${secure&&!https?'<p class="expected">To zgodny wynik dla HTTP, ale nie pełne potwierdzenie cookie Secure. Uruchom HTTPS i powtórz T6 według zakładki „Instrukcja i Postman”.</p>':''}`,headers:i.headers,cookie:i.cookie,fullHttpsHardening:secure&&https&&i.cookie.secure,why:'Nagłówki odczytano z aktywnej odpowiedzi serwera, a właściwości cookie z konfiguracji sesji. Postman pozwala dodatkowo sprawdzić rzeczywisty nagłówek Set-Cookie; test przeglądarkowy sprawdza flagi cookie zapisane przez Chrome.',request:'GET /lab/test-info\nCookie: [sesja po logowaniu]',response:JSON.stringify({httpStatus:200,protocol:location.protocol,headers:i.headers,cookie:i.cookie},null,2)});
}
function lock(value) {
 busy=value;
 document.querySelectorAll('.run-test,#run-all,[data-mode],#reset-xss,#restore-profile').forEach(button=>button.disabled=value||(button.id==='restore-profile'&&!$('#live-profile-baseline').textContent.startsWith('Profil sprzed')));
}
async function run(id) {
 const card=$(`#card-${id}`);
 card.classList.add('is-running');
 card.scrollIntoView({behavior:'smooth',block:'start'});
 $(`#result-${id}`).innerHTML='<p class="running" role="status">Wykonywanie rzeczywistego testu…</p>';
 try { return id==='T1'||id==='T2'?await xss(id):id==='T6'?await t6():await csrf(id,id==='T5'?'good':id==='T4'?'bad':'none'); }
 catch(error) {
  $(`#result-${id}`).innerHTML=`<div class="result-banner fail">Test nie został ukończony: ${esc(error.message)}</div>`;
  if(info){const key=id==='T1'||id==='T2'?'XSS':id;delete evidence[info.mode]?.[key];try{sessionStorage.setItem('hsd-evidence',JSON.stringify(evidence));}catch{}compare();}
  return false;
 } finally { card.classList.remove('is-running'); }
}
document.querySelectorAll('.run-test').forEach(button=>button.addEventListener('click',async()=>{
 if(busy)return;lock(true);try{await run(button.dataset.test);$(`#result-${button.dataset.test}`).scrollIntoView({behavior:'smooth',block:'start'});}finally{lock(false);}
}));
$('#run-all').addEventListener('click',async()=>{
 if(busy)return;lock(true);
 const ids=[...document.querySelectorAll('.run-test')].map(button=>button.dataset.test);
 let passed=0;
 try {
  for(const [index,id] of ids.entries()){$('#all-summary').textContent=`Trwa test ${index+1}/${ids.length}: ${id}`;if(await run(id))passed++;}
  $('#all-summary').textContent=`${passed}/${ids.length} scenariuszy potwierdzonych. ${info.mode==='vulnerable'?'Teraz włącz ochronę i powtórz testy.':'Sprawdź porównanie BEFORE → AFTER poniżej.'}`;
  $('#comparison-results').scrollIntoView({behavior:'smooth',block:'start'});
 } finally { lock(false); }
});
$('#export-report').addEventListener('click',()=>{
 const blob=new Blob([JSON.stringify({project:'P7 — Browser Hardening',exportedAt:new Date().toISOString(),scope:'localhost; kontrolowane testy własnego konta',limitations:['CSRF: test walidacji tokenu w tej samej sesji, nie dowód cross-site.','HTTP: Secure cookie wymaga osobnego testu HTTPS.','Dane sesji cookie pochodzą z konfiguracji serwera; sprawdź Set-Cookie w Postmanie.'],results:evidence},null,2)],{type:'application/json'});
 const url=URL.createObjectURL(blob);const link=document.createElement('a');link.href=url;link.download='P7-evidence-before-after.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
});
compare();

window.addEventListener('resize',()=>document.querySelectorAll('.probe-frame').forEach(fitFrame));
