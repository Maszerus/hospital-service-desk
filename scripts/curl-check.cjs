const {execFile}=require('node:child_process');
const path=require('node:path');
const assert=require('node:assert/strict');
process.env.DB_PATH=':memory:';
process.env.APP_MODE='vulnerable';
const app=require('../app');
const db=require('../src/database/db');
(async()=>{
 const server=app.listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));
 try{
  const output=await new Promise((resolve,reject)=>execFile('sh',[path.join(__dirname,'demo-curl.sh'),'http://127.0.0.1:'+server.address().port],{timeout:30000,maxBuffer:1024*1024},(error,stdout)=>error?reject(error):resolve(stdout)));
  assert.equal((output.match(/HTTP\/1.1 403 Forbidden/g)||[]).length,2);
  assert.equal((output.match(/Profil pozostaje zmieniony = True/g)||[]).length,2);
  assert.match(output,/XSS: cURL i Postman pokazują HTML/);
  console.log('Skrypt cURL: sesja i token poprawne, BEFORE/AFTER, 2×403, losowe dane pozostają zapisane w obu trybach.');
 }finally{await new Promise(r=>server.close(r));db.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
