const express = require('express'), Database = require('better-sqlite3'), bcrypt = require('bcryptjs'),
  jwt = require('jsonwebtoken'), multer = require('multer'), path = require('path'), fs = require('fs'), crypto = require('crypto');

const SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.JWT_SECRET) console.warn('تنبيه: JWT_SECRET غير مضبوط، سيتسجّل خروج الجميع عند كل إعادة تشغيل.');
fs.mkdirSync('uploads', { recursive: true });

const db = new Database('data.db'); db.pragma('journal_mode = WAL');
db.exec(`
create table if not exists users(id integer primary key, name text unique, pass text);
create table if not exists videos(id integer primary key, user_id integer, file text, caption text, created integer default(strftime('%s','now')));
create table if not exists likes(user_id integer, video_id integer, primary key(user_id, video_id));
create table if not exists comments(id integer primary key, user_id integer, video_id integer, body text, created integer default(strftime('%s','now')));
create table if not exists follows(follower integer, followee integer, primary key(follower, followee));`);

const app = express();
app.use(express.json());
app.use((req, res, next) => { // يقرأ التوكن إن وُجد
  try { req.u = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET); } catch { req.u = null; }
  next();
});
const must = (req, res) => req.u || (res.status(401).json({ error: 'سجّل الدخول أولًا' }), null);

const up = multer({
  storage: multer.diskStorage({ destination: 'uploads', filename: (r, f, cb) => cb(null, crypto.randomUUID() + path.extname(f.originalname).toLowerCase().slice(0, 6)) }),
  limits: { fileSize: 100 * 1024 * 1024 },
  fileFilter: (r, f, cb) => cb(null, /^video\//.test(f.mimetype))
});

const token = u => jwt.sign({ id: u.id, name: u.name }, SECRET, { expiresIn: '30d' });
const cred = b => /^[A-Za-z0-9_]{3,20}$/.test(b.name || '') && (b.pass || '').length >= 6;

app.post('/api/register', (req, res) => {
  if (!cred(req.body)) return res.status(400).json({ error: 'الاسم 3-20 حرفًا إنجليزيًا/أرقام/_ وكلمة المرور 6 على الأقل' });
  try {
    const r = db.prepare('insert into users(name,pass) values(?,?)').run(req.body.name, bcrypt.hashSync(req.body.pass, 10));
    res.json({ token: token({ id: r.lastInsertRowid, name: req.body.name }), name: req.body.name });
  } catch { res.status(409).json({ error: 'الاسم مستخدم' }); }
});
app.post('/api/login', (req, res) => {
  const u = db.prepare('select * from users where name=?').get(req.body.name || '');
  if (!u || !bcrypt.compareSync(req.body.pass || '', u.pass)) return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
  res.json({ token: token(u), name: u.name });
});

const SEL = `select v.id, v.file, v.caption, u.name,
 (select count(*) from likes where video_id=v.id) likes,
 (select count(*) from comments where video_id=v.id) comments,
 exists(select 1 from likes where video_id=v.id and user_id=@me) liked,
 exists(select 1 from follows where follower=@me and followee=v.user_id) following
 from videos v join users u on u.id=v.user_id`;

app.get('/api/feed', (req, res) =>
  res.json(db.prepare(SEL + ' order by v.created desc limit 50').all({ me: req.u ? req.u.id : 0 })));

app.post('/api/videos', (req, res, next) => (must(req, res) ? next() : 0), up.single('video'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'اختر ملف فيديو' });
  db.prepare('insert into videos(user_id,file,caption) values(?,?,?)').run(req.u.id, req.file.filename, String(req.body.caption || '').slice(0, 200));
  res.json({ ok: true });
});

app.post('/api/videos/:id/like', (req, res) => {
  if (!must(req, res)) return;
  const k = [req.u.id, +req.params.id];
  const r = db.prepare('delete from likes where user_id=? and video_id=?').run(...k);
  if (!r.changes) db.prepare('insert or ignore into likes values(?,?)').run(...k);
  res.json({ liked: !r.changes, likes: db.prepare('select count(*) c from likes where video_id=?').get(k[1]).c });
});

app.get('/api/videos/:id/comments', (req, res) =>
  res.json(db.prepare('select c.body, u.name from comments c join users u on u.id=c.user_id where video_id=? order by c.id').all(+req.params.id)));
app.post('/api/videos/:id/comments', (req, res) => {
  if (!must(req, res)) return;
  const b = String(req.body.body || '').trim().slice(0, 300);
  if (!b) return res.status(400).json({ error: 'اكتب تعليقًا' });
  db.prepare('insert into comments(user_id,video_id,body) values(?,?,?)').run(req.u.id, +req.params.id, b);
  res.json({ ok: true });
});

app.post('/api/users/:name/follow', (req, res) => {
  if (!must(req, res)) return;
  const t = db.prepare('select id from users where name=?').get(req.params.name);
  if (!t || t.id === req.u.id) return res.status(400).json({ error: 'غير ممكن' });
  const r = db.prepare('delete from follows where follower=? and followee=?').run(req.u.id, t.id);
  if (!r.changes) db.prepare('insert into follows values(?,?)').run(req.u.id, t.id);
  res.json({ following: !r.changes });
});

app.get('/api/users/:name', (req, res) => {
  const u = db.prepare('select id,name from users where name=?').get(req.params.name);
  if (!u) return res.status(404).json({ error: 'غير موجود' });
  res.json({
    name: u.name,
    followers: db.prepare('select count(*) c from follows where followee=?').get(u.id).c,
    following: db.prepare('select count(*) c from follows where follower=?').get(u.id).c,
    videos: db.prepare(SEL + ' where v.user_id=@u order by v.created desc').all({ me: req.u ? req.u.id : 0, u: u.id })
  });
});

app.use('/uploads', express.static('uploads'));
app.use(express.static('public'));
app.use((err, req, res, next) => res.status(400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? 'الفيديو أكبر من 100 ميجا' : 'خطأ في الطلب' }));
app.listen(process.env.PORT || 3000, () => console.log('يعمل على http://localhost:' + (process.env.PORT || 3000)));
