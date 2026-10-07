#!/bin/sh
set -eu
mkdir -p .certs
openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -keyout .certs/localhost-key.pem -out .certs/localhost-cert.pem \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
printf '\nCertyfikat lokalny utworzony. Uruchom: npm run start:https\n'
