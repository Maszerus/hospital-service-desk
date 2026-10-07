const {execFile}=require('node:child_process');
const os=require('node:os');
const path=require('node:path');
const fs=require('node:fs');
const https=require('node:https');
process.env.DB_PATH=':memory:';
process.env.APP_MODE='vulnerable';
const app=require('../app');
const db=require('../src/database/db');
async function run(baseUrl){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'hsd-postman-'));
 const report=path.join(dir,'report.json');
 try{
  await new Promise((resolve,reject)=>execFile('npx',['--yes','newman@6.2.2','run',path.join(__dirname,'../postman/BAI-P7.postman_collection.json'),'--env-var','baseUrl='+baseUrl,'--insecure','--timeout-request','10000','--reporters','json','--reporter-json-export',report],{timeout:120000,maxBuffer:1024*1024},(error)=>{
   // Raport może zawierać cookie i tokeny. Nie wypisujemy go i usuwamy po analizie.
   if(error&&!fs.existsSync(report))return reject(new Error('Nie udało się uruchomić Newman: '+error.message));
   resolve();
  }));
  const summary=JSON.parse(fs.readFileSync(report));
  const failures=summary.run.failures.map(f=>({test:f.error.test,message:f.error.message,request:f.source?.name}));
  if(failures.length)throw new Error(JSON.stringify(failures,null,2));
  return {protocol:baseUrl.split(':')[0],requests:summary.run.stats.requests.total,assertions:summary.run.stats.assertions.total,failures:0};
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
}
(async()=>{
 const server=app.listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));let tls;
 try{
  const results=[await run('http://127.0.0.1:'+server.address().port)];
  if(fs.existsSync('.certs/localhost-key.pem')){
   tls=https.createServer({key:fs.readFileSync('.certs/localhost-key.pem'),cert:fs.readFileSync('.certs/localhost-cert.pem')},app).listen(0,'127.0.0.1');await new Promise(r=>tls.once('listening',r));results.push(await run('https://127.0.0.1:'+tls.address().port));
  }
  fs.writeFileSync('evidence/postman-results.json',JSON.stringify({scope:'Newman uruchomił rzeczywistą kolekcję Postmana na własnej bazie in-memory. HTTP i opcjonalnie lokalne HTTPS.',results},null,2));
  for(const result of results)console.log(`${result.protocol.toUpperCase()}: ${result.requests} żądań, ${result.assertions} asercji, ${result.failures} błędów`);
 }finally{await new Promise(r=>server.close(r));if(tls)await new Promise(r=>tls.close(r));db.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
