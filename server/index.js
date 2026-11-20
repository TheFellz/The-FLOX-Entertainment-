require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { Pool } = require('pg');

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : undefined });
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || 'development-only-change-this-secret-before-deploying';
const uploadDir = path.resolve(process.env.UPLOAD_DIR || 'uploads');
fs.mkdirSync(uploadDir, { recursive: true });
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));
app.use(cookieParser());
app.use('/uploads', express.static(uploadDir, { fallthrough: false, maxAge: '7d' }));
app.use(express.static(path.join(__dirname, '..', 'public')));
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: true, legacyHeaders: false });

function signToken(user) { return jwt.sign({ sub: user.id, email: user.email, owner: user.is_owner }, JWT_SECRET, { expiresIn: '12h' }); }
async function auth(req, res, next) {
  try {
    const token = req.cookies.tfe_session || (req.headers.authorization || '').replace(/^Bearer /, '');
    if (!token) return res.status(401).json({ error: 'Требуется авторизация' });
    const payload = jwt.verify(token, JWT_SECRET);
    const { rows } = await pool.query('SELECT id,email,display_name,is_active,is_owner FROM users WHERE id=$1', [payload.sub]);
    if (!rows[0] || !rows[0].is_active) return res.status(401).json({ error: 'Аккаунт недоступен' });
    req.user = rows[0]; next();
  } catch { return res.status(401).json({ error: 'Сессия истекла. Войдите снова.' }); }
}
async function optionalAuth(req,res,next) { try { const token=req.cookies.tfe_session; if(token){ const p=jwt.verify(token,JWT_SECRET); const q=await pool.query('SELECT id,email,display_name,is_active,is_owner FROM users WHERE id=$1',[p.sub]); if(q.rows[0]?.is_active) req.user=q.rows[0]; } next(); } catch { next(); } }
function ownerOnly(req, res, next) { if (!req.user?.is_owner) return res.status(403).json({ error: 'Только владелец может выполнить это действие' }); next(); }
async function can(req, permission) {
  if (req.user.is_owner) return true;
  const q = await pool.query(`SELECT 1 FROM user_roles ur JOIN role_permissions rp ON rp.role_id=ur.role_id JOIN permissions p ON p.id=rp.permission_id WHERE ur.user_id=$1 AND p.code=$2 LIMIT 1`, [req.user.id, permission]);
  return q.rowCount > 0;
}
function permit(permission) { return async (req,res,next) => { try { if (await can(req, permission)) return next(); res.status(403).json({error:'Недостаточно прав'}); } catch(e){ next(e); } }; }
async function audit(req, action, type='', id='', details={}) { await pool.query('INSERT INTO audit_logs(actor_id,action,entity_type,entity_id,details) VALUES($1,$2,$3,$4,$5)', [req.user?.id || null, action, type, String(id || ''), JSON.stringify(details)]); }
function slugify(s) { return String(s).toLowerCase().trim().replace(/[^a-zа-яё0-9]+/gi,'-').replace(/^-|-$/g,'') || `item-${Date.now()}`; }

app.get('/api/health', async (_req,res) => { try { await pool.query('SELECT 1'); res.json({status:'ok',database:'connected'}); } catch { res.status(503).json({status:'error',database:'unavailable'}); } });
app.post('/api/auth/login', authLimiter, async (req,res,next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase(); const password = String(req.body.password || '');
    if (!email || !password) return res.status(400).json({error:'Укажите email и пароль'});
    const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [email]); const user = rows[0];
    if (!user || !user.is_active || !(await bcrypt.compare(password,user.password_hash))) return res.status(401).json({error:'Неверный email или пароль'});
    await pool.query('UPDATE users SET last_login_at=NOW() WHERE id=$1',[user.id]);
    res.cookie('tfe_session', signToken(user), { httpOnly:true, secure:process.env.COOKIE_SECURE==='true', sameSite:'strict', maxAge:12*60*60*1000, path:'/' });
    await audit({user},'auth.login','user',user.id);
    res.json({user:{id:user.id,email:user.email,name:user.display_name,isOwner:user.is_owner}});
  } catch(e){ next(e); }
});
app.post('/api/auth/logout', (_req,res) => { res.clearCookie('tfe_session',{httpOnly:true,sameSite:'strict',path:'/'}); res.json({ok:true}); });
app.get('/api/auth/me', auth, async (req,res) => { const roles=await pool.query('SELECT r.name FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=$1',[req.user.id]); res.json({user:{id:req.user.id,email:req.user.email,name:req.user.display_name,isOwner:req.user.is_owner,roles:roles.rows.map(x=>x.name)}}); });

app.post('/api/team', auth, ownerOnly, async (req,res,next) => {
  try { const {email,name,password,role='Employee'}=req.body; if(!email||!name||!password||String(password).length<10) return res.status(400).json({error:'Нужны имя, email и пароль не короче 10 символов'});
    const hash=await bcrypt.hash(password,12); const u=await pool.query('INSERT INTO users(email,display_name,password_hash) VALUES($1,$2,$3) RETURNING id,email,display_name,is_active',[String(email).toLowerCase(),name,hash]);
    const r=await pool.query('SELECT id FROM roles WHERE name=$1',[role]); if(r.rows[0]) await pool.query('INSERT INTO user_roles(user_id,role_id) VALUES($1,$2) ON CONFLICT DO NOTHING',[u.rows[0].id,r.rows[0].id]);
    await audit(req,'team.user_created','user',u.rows[0].id,{email,role}); res.status(201).json({user:u.rows[0]});
  } catch(e){ if(e.code==='23505') return res.status(409).json({error:'Пользователь с таким email уже существует'}); next(e); }
});
app.get('/api/team', auth, permit('workspace.view'), async (_req,res,next) => { try { const q=await pool.query('SELECT u.id,u.email,u.display_name,u.is_active,u.is_owner,u.created_at,COALESCE(array_agg(r.name) FILTER (WHERE r.name IS NOT NULL), ARRAY[]::text[]) roles FROM users u LEFT JOIN user_roles ur ON ur.user_id=u.id LEFT JOIN roles r ON r.id=ur.role_id GROUP BY u.id ORDER BY u.created_at'); res.json(q.rows); } catch(e){next(e);} });
app.patch('/api/team/:id/status', auth, ownerOnly, async (req,res,next) => { try { const q=await pool.query('UPDATE users SET is_active=$1 WHERE id=$2 AND is_owner=FALSE RETURNING id,is_active',[!!req.body.active,req.params.id]); if(!q.rowCount) return res.status(404).json({error:'Сотрудник не найден или это владелец'}); await audit(req,'team.user_status_changed','user',req.params.id,{active:!!req.body.active}); res.json(q.rows[0]); }catch(e){next(e);} });

app.get('/api/projects', optionalAuth, async (req,res,next) => { try { let q; if(req.user) q=await pool.query('SELECT p.*,u.display_name lead_name FROM projects p LEFT JOIN users u ON u.id=p.lead_id ORDER BY p.updated_at DESC'); else q=await pool.query('SELECT p.id,p.title,p.slug,p.summary,p.description,p.category,p.status,p.cover_url,p.logo_url,p.progress,p.created_at,p.updated_at FROM projects p WHERE p.is_public=TRUE ORDER BY p.updated_at DESC'); res.json(q.rows); }catch(e){next(e);} });
app.post('/api/projects', auth, permit('projects.manage'), async (req,res,next) => { try { const b=req.body; const q=await pool.query('INSERT INTO projects(title,slug,summary,description,category,status,cover_url,lead_id,progress,is_public) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *',[b.title,slugify(b.slug||b.title),b.summary||'',b.description||'',b.category||'Other',b.status||'Идея',b.cover_url||'',b.lead_id||null,Number(b.progress||0),!!b.is_public]); await audit(req,'project.created','project',q.rows[0].id); res.status(201).json(q.rows[0]); }catch(e){next(e);} });
app.patch('/api/projects/:id', auth, permit('projects.manage'), async (req,res,next) => { try { const b=req.body; const q=await pool.query(`UPDATE projects SET title=COALESCE($1,title),summary=COALESCE($2,summary),description=COALESCE($3,description),status=COALESCE($4,status),progress=COALESCE($5,progress),is_public=COALESCE($6,is_public),updated_at=NOW() WHERE id=$7 RETURNING *`,[b.title,b.summary,b.description,b.status,b.progress,b.is_public,req.params.id]); if(!q.rowCount)return res.status(404).json({error:'Проект не найден'}); await audit(req,'project.updated','project',req.params.id); res.json(q.rows[0]); }catch(e){next(e);} });

app.get('/api/tasks', auth, permit('workspace.view'), async (_req,res,next)=>{try{const q=await pool.query('SELECT t.*,p.title project_title,u.display_name assignee_name FROM tasks t LEFT JOIN projects p ON p.id=t.project_id LEFT JOIN users u ON u.id=t.assignee_id ORDER BY t.due_at NULLS LAST,t.created_at DESC');res.json(q.rows);}catch(e){next(e);}});
app.post('/api/tasks', auth, permit('tasks.manage'), async(req,res,next)=>{try{const b=req.body;if(!b.title)return res.status(400).json({error:'Введите название задачи'});const q=await pool.query('INSERT INTO tasks(project_id,title,description,status,priority,assignee_id,due_at,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',[b.project_id||null,b.title,b.description||'',b.status||'К выполнению',b.priority||'Средний',b.assignee_id||null,b.due_at||null,req.user.id]);await audit(req,'task.created','task',q.rows[0].id);res.status(201).json(q.rows[0]);}catch(e){next(e);}});
app.patch('/api/tasks/:id',auth,permit('tasks.manage'),async(req,res,next)=>{try{const b=req.body;const q=await pool.query('UPDATE tasks SET title=COALESCE($1,title),description=COALESCE($2,description),status=COALESCE($3,status),priority=COALESCE($4,priority),assignee_id=COALESCE($5,assignee_id),due_at=COALESCE($6,due_at),updated_at=NOW() WHERE id=$7 RETURNING *',[b.title,b.description,b.status,b.priority,b.assignee_id,b.due_at,req.params.id]);if(!q.rowCount)return res.status(404).json({error:'Задача не найдена'});await audit(req,'task.updated','task',req.params.id);res.json(q.rows[0]);}catch(e){next(e);}});

app.get('/api/news', async (_req,res,next)=>{try{const q=await pool.query('SELECT n.id,n.title,n.slug,n.excerpt,n.body,n.cover_url,n.published_at,u.display_name author FROM news n LEFT JOIN users u ON u.id=n.author_id WHERE n.published=TRUE ORDER BY n.published_at DESC NULLS LAST');res.json(q.rows);}catch(e){next(e);}});
app.post('/api/news',auth,permit('news.manage'),async(req,res,next)=>{try{const b=req.body;const q=await pool.query('INSERT INTO news(title,slug,excerpt,body,cover_url,published,published_at,author_id) VALUES($1,$2,$3,$4,$5,$6,CASE WHEN $6 THEN NOW() ELSE NULL END,$7) RETURNING *',[b.title,slugify(b.slug||b.title),b.excerpt||'',b.body||'',b.cover_url||'',!!b.published,req.user.id]);await audit(req,'news.created','news',q.rows[0].id);res.status(201).json(q.rows[0]);}catch(e){next(e);}});
app.get('/api/achievements',async(_req,res,next)=>{try{res.json((await pool.query('SELECT * FROM achievements WHERE is_public=TRUE ORDER BY sort_order,date_label DESC')).rows);}catch(e){next(e);}});
app.get('/api/partners',async(_req,res,next)=>{try{res.json((await pool.query('SELECT * FROM partners WHERE is_public=TRUE ORDER BY name')).rows);}catch(e){next(e);}});
app.get('/api/jobs',async(_req,res,next)=>{try{res.json((await pool.query('SELECT * FROM job_openings WHERE is_open=TRUE ORDER BY created_at DESC')).rows);}catch(e){next(e);}});
app.post('/api/contact',authLimiter,async(req,res,next)=>{try{const b=req.body;if(!b.name||!b.email||!b.message)return res.status(400).json({error:'Заполните имя, email и сообщение'});await pool.query('INSERT INTO contact_messages(name,email,subject,message) VALUES($1,$2,$3,$4)',[b.name,b.email,b.subject||'',b.message]);res.status(201).json({ok:true,message:'Сообщение отправлено'});}catch(e){next(e);}});

app.get('/api/events',auth,permit('workspace.view'),async(_req,res,next)=>{try{res.json((await pool.query('SELECT e.*,p.title project_title FROM events e LEFT JOIN projects p ON p.id=e.project_id ORDER BY starts_at')).rows);}catch(e){next(e);}});
app.post('/api/events',auth,permit('calendar.manage'),async(req,res,next)=>{try{const b=req.body;const q=await pool.query('INSERT INTO events(title,description,starts_at,ends_at,project_id,created_by) VALUES($1,$2,$3,$4,$5,$6) RETURNING *',[b.title,b.description||'',b.starts_at,b.ends_at||null,b.project_id||null,req.user.id]);await audit(req,'event.created','event',q.rows[0].id);res.status(201).json(q.rows[0]);}catch(e){next(e);}});
app.post('/api/team/:id/roles',auth,ownerOnly,async(req,res,next)=>{try{const role=await pool.query('SELECT id FROM roles WHERE name=$1',[req.body.role]);if(!role.rowCount)return res.status(404).json({error:'Роль не найдена'});await pool.query('DELETE FROM user_roles WHERE user_id=$1',[req.params.id]);await pool.query('INSERT INTO user_roles(user_id,role_id) VALUES($1,$2)',[req.params.id,role.rows[0].id]);await audit(req,'team.role_changed','user',req.params.id,{role:req.body.role});res.json({ok:true});}catch(e){next(e);}});
app.post('/api/channels',auth,permit('messages.use'),async(req,res,next)=>{try{const b=req.body;if(!b.name)return res.status(400).json({error:'Укажите название канала'});const q=await pool.query('INSERT INTO channels(name,kind,project_id) VALUES($1,$2,$3) RETURNING *',[b.name,b.kind||'group',b.project_id||null]);await pool.query('INSERT INTO channel_members(channel_id,user_id) VALUES($1,$2)',[q.rows[0].id,req.user.id]);for(const id of (b.member_ids||[])){await pool.query('INSERT INTO channel_members(channel_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING',[q.rows[0].id,id]);}await audit(req,'channel.created','channel',q.rows[0].id);res.status(201).json(q.rows[0]);}catch(e){next(e);}});
app.get('/api/channels',auth,permit('messages.use'),async(req,res,next)=>{try{const q=await pool.query('SELECT c.* FROM channels c LEFT JOIN channel_members cm ON cm.channel_id=c.id WHERE c.kind IN (\'company\',\'department\') OR cm.user_id=$1 GROUP BY c.id ORDER BY c.name',[req.user.id]);res.json(q.rows);}catch(e){next(e);}});
app.get('/api/channels/:id/messages',auth,permit('messages.use'),async(req,res,next)=>{try{const allowed=await pool.query('SELECT 1 FROM channels c LEFT JOIN channel_members cm ON cm.channel_id=c.id WHERE c.id=$1 AND (c.kind IN (\'company\',\'department\') OR cm.user_id=$2)',[req.params.id,req.user.id]);if(!allowed.rowCount)return res.status(403).json({error:'Нет доступа к каналу'});res.json((await pool.query('SELECT m.*,u.display_name sender_name FROM messages m LEFT JOIN users u ON u.id=m.sender_id WHERE channel_id=$1 ORDER BY created_at LIMIT 200',[req.params.id])).rows);}catch(e){next(e);}});
app.post('/api/channels/:id/messages',auth,permit('messages.use'),async(req,res,next)=>{try{const b=req.body;const q=await pool.query('INSERT INTO messages(channel_id,sender_id,body,reply_to) SELECT c.id,$2,$3,$4 FROM channels c LEFT JOIN channel_members cm ON cm.channel_id=c.id WHERE c.id=$1 AND (c.kind IN (\'company\',\'department\') OR cm.user_id=$2) RETURNING *',[req.params.id,req.user.id,b.body,b.reply_to||null]);if(!q.rowCount)return res.status(403).json({error:'Нет доступа к каналу'});res.status(201).json(q.rows[0]);}catch(e){next(e);}});
app.get('/api/documents',auth,permit('workspace.view'),async(_req,res,next)=>{try{res.json((await pool.query('SELECT d.*,u.display_name owner_name FROM documents d LEFT JOIN users u ON u.id=d.owner_id ORDER BY updated_at DESC')).rows);}catch(e){next(e);}});
app.post('/api/documents',auth,permit('documents.manage'),async(req,res,next)=>{try{const b=req.body;const q=await pool.query('INSERT INTO documents(title,category,body,status,owner_id) VALUES($1,$2,$3,$4,$5) RETURNING *',[b.title,b.category||'Общее',b.body||'',b.status||'Черновик',req.user.id]);await audit(req,'document.created','document',q.rows[0].id);res.status(201).json(q.rows[0]);}catch(e){next(e);}});
app.get('/api/notifications',auth,async(req,res,next)=>{try{res.json((await pool.query('SELECT * FROM notifications WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100',[req.user.id])).rows);}catch(e){next(e);}});
app.patch('/api/notifications/:id/read',auth,async(req,res,next)=>{try{await pool.query('UPDATE notifications SET read_at=NOW() WHERE id=$1 AND user_id=$2',[req.params.id,req.user.id]);res.json({ok:true});}catch(e){next(e);}});
app.get('/api/audit',auth,permit('audit.view'),async(_req,res,next)=>{try{res.json((await pool.query('SELECT a.*,u.display_name actor_name FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.created_at DESC LIMIT 300')).rows);}catch(e){next(e);}});
app.get('/api/roles',auth,ownerOnly,async(_req,res,next)=>{try{const roles=await pool.query('SELECT * FROM roles ORDER BY name');const perms=await pool.query('SELECT * FROM permissions ORDER BY code');res.json({roles:roles.rows,permissions:perms.rows});}catch(e){next(e);}});
app.post('/api/roles',auth,ownerOnly,async(req,res,next)=>{try{const q=await pool.query('INSERT INTO roles(name,description) VALUES($1,$2) RETURNING *',[req.body.name,req.body.description||'']);res.status(201).json(q.rows[0]);}catch(e){next(e);}});
app.put('/api/roles/:id/permissions',auth,ownerOnly,async(req,res,next)=>{const client=await pool.connect();try{await client.query('BEGIN');await client.query('DELETE FROM role_permissions WHERE role_id=$1',[req.params.id]);for(const code of (req.body.permissions||[])){await client.query('INSERT INTO role_permissions(role_id,permission_id) SELECT $1,id FROM permissions WHERE code=$2 ON CONFLICT DO NOTHING',[req.params.id,code]);}await client.query('COMMIT');await audit(req,'role.permissions_updated','role',req.params.id);res.json({ok:true});}catch(e){await client.query('ROLLBACK');next(e);}finally{client.release();}});
const storage=multer.diskStorage({destination:(_r,_f,cb)=>cb(null,uploadDir),filename:(_r,f,cb)=>cb(null,`${Date.now()}-${Math.random().toString(36).slice(2)}${path.extname(f.originalname).slice(0,10)}`)});
app.post('/api/upload',auth,permit('documents.manage'),multer({storage,limits:{fileSize:20*1024*1024},fileFilter:(_r,f,cb)=>{const ok=/^(image\/(png|jpeg|webp|gif)|application\/pdf|text\/plain|application\/zip|video\/mp4)$/.test(f.mimetype);cb(ok?null:new Error('Тип файла не поддерживается'),ok);}}).single('file'),async(req,res)=>{if(!req.file)return res.status(400).json({error:'Файл не получен'});await audit(req,'file.uploaded','file',req.file.filename);res.status(201).json({url:`/uploads/${req.file.filename}`,name:req.file.originalname,size:req.file.size});});

app.use('/api',(_req,res)=>res.status(404).json({error:'API endpoint not found'}));
app.use((err,_req,res,_next)=>{console.error(err);const status=err.status||500;res.status(status).json({error:status===500?'Внутренняя ошибка сервера':err.message});});
app.get('*',(_req,res)=>res.sendFile(path.join(__dirname,'..','public','index.html')));
app.listen(PORT,()=>console.log(`TFE platform listening on http://localhost:${PORT}`));
