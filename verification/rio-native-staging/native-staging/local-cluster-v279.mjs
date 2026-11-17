import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdtemp,mkdir,readFile,appendFile,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {randomBytes} from 'node:crypto';
import pg from 'pg';
import {initdb,pg_ctl} from '@embedded-postgres/linux-x64';
import {hydrateSymlinks} from './node_modules/@embedded-postgres/linux-x64/scripts/hydrate-symlinks.js';

const run=promisify(execFile);
export async function startLocalClusterV279() {
  if(process.platform!=='linux'||process.arch!=='x64'||process.getuid?.()===0)
    throw Error('LINUX_X64_NON_ROOT_REQUIRED');
  const packageRoot=fileURLToPath(new URL('./node_modules/@embedded-postgres/linux-x64/',import.meta.url));
  const links=JSON.parse(await readFile(join(packageRoot,'native/pg-symlinks.json'),'utf8'));
  for(const item of links)for(const key of ['source','target']){
    if(!resolve(packageRoot,item[key]).startsWith(resolve(packageRoot)+sep))throw Error('DEPENDENCY_LINK_OUTSIDE_PACKAGE');
  }
  await hydrateSymlinks();
  const root=await mkdtemp(join(tmpdir(),'rio-v279-'));
  const data=join(root,'data'),socket=join(root,'socket');
  await mkdir(socket,{mode:0o700});
  const clients=new Set(),passwords={};
  let started=false,closed=false;
  const base={host:socket,port:56479,database:'postgres',ssl:false,
    application_name:'rio_native_v279',connectionTimeoutMillis:5000,
    options:'-c statement_timeout=10000 -c lock_timeout=5000'};
  async function connect(user='rio_fixture_owner',passwordOverride) {
    const client=new pg.Client({...base,user,password:passwordOverride??passwords[user]??'local-owner-unused'});
    client.on('error',()=>{});
    try{await client.connect();}catch(error){await client.end().catch(()=>{});throw error;}
    clients.add(client);
    const end=client.end.bind(client);
    client.end=async()=>{if(clients.delete(client))await end();};
    return client;
  }
  async function start(){
    try{await run(pg_ctl,['-D',data,'-l',join(root,'server.log'),'-w','-t','15','start']);started=true;}
    catch{throw Error('LOCAL_POSTGRES_START_FAILED: '+await readFile(join(root,'server.log'),'utf8').catch(()=> 'NO_LOG'));}
  }
  async function stop(){
    for(const client of [...clients])await client.end().catch(()=>{});
    if(started){await run(pg_ctl,['-D',data,'-m','fast','-w','-t','15','stop']);started=false;}
  }
  async function close(){
    if(closed)return;closed=true;
    try{await stop();}finally{await rm(root,{recursive:true,force:true});}
  }
  try{
    await run(initdb,['-D',data,'--username=rio_fixture_owner','--encoding=UTF8','--no-locale',
      '--auth-local=trust','--auth-host=scram-sha-256']);
    await appendFile(join(data,'postgresql.conf'),`\nlisten_addresses = ''\nunix_socket_directories = '${socket}'\nunix_socket_permissions = 0700\nport = 56479\nmax_connections = 16\nfsync = on\nsynchronous_commit = on\npassword_encryption = 'scram-sha-256'\nlog_statement = 'none'\n`);
    await writeFile(join(data,'pg_hba.conf'),'local all rio_fixture_owner trust\nlocal all all scram-sha-256\n');
    await start();
    return {connect,stop,start,close,
      provisionLogin:async(admin,user)=>{
        if(!['rio_v276_reader','rio_v276_writer'].includes(user))throw Error('FIXED_FIXTURE_ROLE_REQUIRED');
        const password=randomBytes(32).toString('hex');passwords[user]=password;
        // Locally generated hex only; no external value enters this DDL.
        await admin.query(`ALTER ROLE ${user} LOGIN PASSWORD '${password}'`);
      }};
  }catch(error){await close().catch(()=>{});throw error;}
}
