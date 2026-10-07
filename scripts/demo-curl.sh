#!/bin/sh
# Odtworzenie HTTP BEFORE/AFTER. Cookie i token mają własną sesję tego skryptu.
set -eu
hsd_base_url=${1:-http://localhost:3000}
hsd_temp_dir=$(mktemp -d)
trap 'rm -rf "$hsd_temp_dir"' EXIT
hsd_cookie_file="$hsd_temp_dir/cookies.txt"
hsd_profile_before="$hsd_temp_dir/profile-before.json"
hsd_profile_after="$hsd_temp_dir/profile-after.json"

hsd_request() {
 hsd_method=$1
 hsd_route=$2
 shift 2
 printf '\n>>> %s %s%s\n' "$hsd_method" "$hsd_base_url" "$hsd_route"
 curl --silent --show-error --include --cookie "$hsd_cookie_file" --cookie-jar "$hsd_cookie_file" \
   --request "$hsd_method" "$hsd_base_url$hsd_route" "$@"
 printf '\n'
}
hsd_get_json() {
 curl --fail --silent --show-error --cookie "$hsd_cookie_file" --cookie-jar "$hsd_cookie_file" "$hsd_base_url$1" > "$2"
}

printf 'Sesja cURL: %s\n' "$hsd_base_url"
hsd_request POST /login --header 'Content-Type: application/json' --data-raw '{"username":"student","password":"student123"}'
for hsd_mode in vulnerable secure; do
 printf '\n=========== TRYB: %s ===========\n' "$hsd_mode"
 hsd_request POST /lab/mode --header 'Content-Type: application/json' --data-raw "{\"mode\":\"$hsd_mode\"}"
 hsd_get_json /lab/profile-state "$hsd_profile_before"
 printf '\nProfil PRZED:\n'
 cat "$hsd_profile_before"
 hsd_get_json /lab/xss-info "$hsd_temp_dir/xss-info.json"
 python3 - "$hsd_temp_dir/xss-info.json" "$hsd_temp_dir/xss-body.json" <<'PY'
import json,sys
with open(sys.argv[1]) as f: info=json.load(f)
with open(sys.argv[2],'w') as f: json.dump({'description':info['payload']},f,ensure_ascii=False)
print('\nDokładny zapisany payload:\n'+info['payload'])
PY
 hsd_request POST /lab/xss-probe --header 'Content-Type: application/json' --data-binary "@$hsd_temp_dir/xss-body.json"
 hsd_request GET /lab/xss-frame
 for hsd_kind in none bad good; do
  if [ "$hsd_kind" = good ] && [ "$hsd_mode" != secure ]; then continue; fi
  hsd_get_json /lab/profile-candidate "$hsd_temp_dir/candidate.json"
  hsd_get_json /lab/test-info "$hsd_temp_dir/info.json"
  python3 - "$hsd_temp_dir/candidate.json" "$hsd_temp_dir/info.json" "$hsd_temp_dir/profile-body.json" "$hsd_kind" <<'PYBODY'
import json,sys
with open(sys.argv[1]) as f: body=json.load(f)
with open(sys.argv[2]) as f: info=json.load(f)
if sys.argv[4]=='bad': body['csrfToken']='INVALID-TOKEN'
if sys.argv[4]=='good': body['csrfToken']=info['csrfToken']
with open(sys.argv[3],'w') as f: json.dump(body,f,ensure_ascii=False)
print('Wylosowany profil:',body['display_name'],body['email'])
PYBODY
  hsd_request POST /lab/profile-probe --header 'Content-Type: application/json' --data-binary "@$hsd_temp_dir/profile-body.json"
 done
 hsd_get_json /lab/profile-state "$hsd_profile_after"
 python3 - "$hsd_profile_before" "$hsd_profile_after" "$hsd_temp_dir/profile-body.json" <<'PY'
import json,sys
with open(sys.argv[1]) as f: before=json.load(f)['profile']
with open(sys.argv[2]) as f: after=json.load(f)['profile']
print('\nProfil PO:',json.dumps(after,ensure_ascii=False))
with open(sys.argv[3]) as f: body=json.load(f)
expected={key:body[key] for key in ['display_name','email']}
print('Profil pozostaje zmieniony =',before!=after and after==expected)
assert before!=after and after==expected, 'Nie potwierdzono utrzymania zapisanej zmiany'
PY
 hsd_request GET /lab/test-info
 done
printf '\nXSS: cURL i Postman pokazują HTML, nie wykonują testu JS w przeglądarce.\n'
printf 'Uruchom T1/T2 w przeglądarce, aby zobaczyć rzeczywiste zmiany DOM.\n'
printf 'Po HTTP flaga Secure=true nie jest sprawdzona; powtórz T6 po HTTPS.\n'
printf 'Zapisany profil pozostaje zmieniony. Ręczne przywrócenie ma osobny przycisk w aplikacji.\n'
