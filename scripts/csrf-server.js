const http = require('http');
const fs = require('fs');
const path = require('path');
http
  .createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(fs.readFileSync(path.join(__dirname, '../csrf-demo.html')));
  })
  .listen(4000, '127.0.0.1', () => console.log('Kontrolowana strona CSRF: http://localhost:4000'));
