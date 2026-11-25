const express=require('express'),{createClient}=require('@libsql/client'),bcrypt=require('bcryptjs'),crypto=require('crypto');
const db=createClient({url:process.env.TURSO_URL,authToken:process.env.TURSO_TOKEN});
const SECRET=process.env.SECRET||'change-me',STAFF=process.env.STAFF_PASSWORD,CODE=process.env.REG_CODE||'';
const app=express();app.use(express.json({limit:'25mb'}));app.use(express.static('public'));
const hm=p=>crypto.createHmac('sha256',SECRET).update(p).digest('base64url');
const sign=o=>{const p=Buffer.from(JSON.stringify({...o,e:Date.now()+864e6})).toString('base64url');return p+'.'+hm(p)};
const verify=t=>{try{const[p,s]=t.split('.');if(s!==hm(p))return;const o=JSON.parse(Buffer.from(p,'base64url'));return o.e>Date.now()?o:null}catch{}};
const auth=r=>(q,s,n)=>{const o=verify(q.headers['x-t']||'');if(!o||o.r!==r)return s.status(401).json({error:'Please log in again'});q.u=o;n()};
const W=f=>(q,s)=>f(q,s).catch(e=>{console.error(e);s.status(500).json({error:'Server error'})});
const all=async(sql,args=[])=>(await db.execute({sql,args})).rows.map(r=>({...r}));
const run=(sql,args=[])=>db.execute({sql,args});
const bad=(s,m,c=400)=>s.status(c).json({error:m});
const ready=db.batch([
`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE,name TEXT,phone TEXT,country TEXT,pw TEXT,status TEXT DEFAULT 'pending',idc TEXT)`,
`CREATE TABLE IF NOT EXISTS briefs(id INTEGER PRIMARY KEY AUTOINCREMENT,day INTEGER,title TEXT,type TEXT,descr TEXT,max_files INTEGER DEFAULT 1,deadline TEXT)`,
`CREATE TABLE IF NOT EXISTS files(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,brief_id INTEGER,data TEXT,late INTEGER DEFAULT 0)`,
`CREATE TABLE IF NOT EXISTS scores(user_id INTEGER,brief_id INTEGER,judge TEXT,c INTEGER,b INTEGER,t INTEGER,p INTEGER,note TEXT,PRIMARY KEY(user_id,brief_id,judge))`]);
// participants
app.post('/api/register',W(async(q,s)=>{await ready;const{email,name,phone,country,password,code}=q.body;
 if(CODE&&code!==CODE)return bad(s,'Wrong registration code. Check your WhatsApp message.');
 if(!email||!name||!phone||!country||!password||password.length<6)return bad(s,'Fill every field (password: 6+ characters).');
 try{await run('INSERT INTO users(email,name,phone,country,pw)VALUES(?,?,?,?,?)',[email.trim().toLowerCase(),name.trim(),phone,country,bcrypt.hashSync(password,8)])}catch{return bad(s,'That email is already registered.')}
 s.json({ok:1})}));
app.post('/api/login',W(async(q,s)=>{await ready;const[u]=await all('SELECT * FROM users WHERE email=?',[(q.body.email||'').trim().toLowerCase()]);
 if(!u||!bcrypt.compareSync(q.body.password||'',u.pw))return bad(s,'Wrong email or password.',401);
 if(u.status!=='approved')return bad(s,'Your registration is still pending approval.',403);
 s.json({t:sign({r:'p',id:u.id}),name:u.name,idc:u.idc})}));
app.get('/api/briefs',auth('p'),W(async(q,s)=>s.json(await all('SELECT b.*,(SELECT COUNT(*) FROM files f WHERE f.brief_id=b.id AND f.user_id=?)n FROM briefs b ORDER BY day',[q.u.id]))));
app.post('/api/submit',auth('p'),W(async(q,s)=>{const[b]=await all('SELECT * FROM briefs WHERE id=?',[q.body.brief_id]);const f=q.body.files||[];
 if(!b||!f.length||f.length>b.max_files||f.some(x=>!/^data:image\//.test(x)))return bad(s,`Upload 1 to ${b?b.max_files:1} image(s).`);
 const late=b.deadline&&Date.now()>Date.parse(b.deadline)?1:0;
 await db.batch([{sql:'DELETE FROM files WHERE user_id=? AND brief_id=?',args:[q.u.id,b.id]},...f.map(d=>({sql:'INSERT INTO files(user_id,brief_id,data,late)VALUES(?,?,?,?)',args:[q.u.id,b.id,d,late]}))]);
 s.json({ok:1,late})}));
// staff
app.post('/api/staff/login',W(async(q,s)=>{const{judge,password}=q.body;if(!STAFF||password!==STAFF||!judge)return bad(s,'Wrong name or password.',401);s.json({t:sign({r:'s',j:judge.trim()}),name:judge.trim()})}));
const S=auth('s');
app.get('/api/staff/pending',S,W(async(q,s)=>s.json(await all("SELECT id,name,email,phone,country FROM users WHERE status='pending' ORDER BY id"))));
app.post('/api/staff/approve',S,W(async(q,s)=>{const[m]=await all("SELECT COALESCE(MAX(CAST(SUBSTR(idc,5) AS INTEGER)),0)n FROM users");
 const idc='IDC-'+String(m.n+1).padStart(3,'0');await run("UPDATE users SET status='approved',idc=? WHERE id=? AND status='pending'",[idc,q.body.id]);s.json({idc})}));
app.post('/api/staff/brief',S,W(async(q,s)=>{await ready;const{day,title,type,descr,max_files,deadline}=q.body;if(!day||!title||!type)return bad(s,'Day, title and type are required.');
 await run('INSERT INTO briefs(day,title,type,descr,max_files,deadline)VALUES(?,?,?,?,?,?)',[day,title,type,descr||'',max_files||1,deadline||null]);s.json({ok:1})}));
app.get('/api/staff/briefs',S,W(async(q,s)=>s.json(await all('SELECT id,day,title,type FROM briefs ORDER BY day'))));
app.get('/api/staff/subs',S,W(async(q,s)=>{const rows=await all('SELECT f.user_id,u.idc,f.data,f.late FROM files f JOIN users u ON u.id=f.user_id WHERE f.brief_id=? ORDER BY u.idc,f.id',[q.query.brief]);
 const mine=await all('SELECT * FROM scores WHERE brief_id=? AND judge=?',[q.query.brief,q.u.j]),g={};
 rows.forEach(r=>{(g[r.user_id]??={uid:r.user_id,idc:r.idc,late:r.late,files:[],mine:mine.find(m=>m.user_id===r.user_id)||null}).files.push(r.data)});s.json(Object.values(g))}));
app.post('/api/staff/score',S,W(async(q,s)=>{const{uid,brief,c,b,t,p,note}=q.body,v=[c,b,t,p].map(Number);if(v.some(x=>!(x>=0&&x<=10)))return bad(s,'Scores must be 0 to 10.');
 await run('INSERT OR REPLACE INTO scores VALUES(?,?,?,?,?,?,?,?)',[uid,brief,q.u.j,...v,note||'']);s.json({ok:1})}));
const board=()=>all('SELECT u.idc,u.name,COUNT(*)briefs,ROUND(SUM(s.bt),1)total FROM users u JOIN(SELECT user_id,brief_id,AVG(c+b+t+p)bt FROM scores GROUP BY user_id,brief_id)s ON s.user_id=u.id GROUP BY u.id ORDER BY total DESC');
app.get('/api/staff/board',S,W(async(q,s)=>s.json(await board())));
app.get('/api/staff/export',S,W(async(q,s)=>{const r=await board();s.json({csv:'Rank,ID,Name,Briefs scored,Total\n'+r.map((x,i)=>[i+1,x.idc,`"${x.name}"`,x.briefs,x.total].join(',')).join('\n')})}));
app.listen(process.env.PORT||3000,()=>console.log('IDC portal running'));
