import { Hono } from 'hono'

type User = { id: number; name: string; email: string; role: string }
type Env = { Bindings: { DB: D1Database }; Variables: { user: User } }
const app = new Hono<Env>()
const enc = new TextEncoder()
const hex = (b: ArrayBuffer | Uint8Array) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('')
const rand = (n: number) => hex(crypto.getRandomValues(new Uint8Array(n)))

async function hashPw(pw: string, salt: string) {
  const key = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits'])
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash: 'SHA-256' }, key, 256))
}

async function newSession(db: D1Database, userId: number) {
  const token = rand(32)
  await db.prepare('INSERT INTO sessions (token, user_id) VALUES (?, ?)').bind(token, userId).run()
  return token
}

app.post('/api/signup', async (c) => {
  const { name, email, password } = await c.req.json()
  if (!name || !email || !password || password.length < 8) return c.json({ error: 'Name, email and a password of 8+ characters are required' }, 400)
  const db = c.env.DB
  const exists = await db.prepare('SELECT id FROM users WHERE email = ?').bind(email.toLowerCase()).first()
  if (exists) return c.json({ error: 'Email already registered' }, 409)
  const count = await db.prepare('SELECT COUNT(*) AS n FROM users').first<{ n: number }>()
  const role = count?.n === 0 ? 'admin' : 'student' // first account becomes admin
  const salt = rand(16)
  const r = await db.prepare('INSERT INTO users (name, email, salt, hash, role) VALUES (?, ?, ?, ?, ?)').bind(name, email.toLowerCase(), salt, await hashPw(password, salt), role).run()
  const id = r.meta.last_row_id as number
  return c.json({ token: await newSession(db, id), user: { id, name, email, role } })
})

app.post('/api/login', async (c) => {
  const { email, password } = await c.req.json()
  const u = await c.env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(String(email || '').toLowerCase()).first<any>()
  if (!u || (await hashPw(String(password || ''), u.salt)) !== u.hash) return c.json({ error: 'Invalid email or password' }, 401)
  return c.json({ token: await newSession(c.env.DB, u.id), user: { id: u.id, name: u.name, email: u.email, role: u.role } })
})

app.use('/api/*', async (c, next) => {
  const token = c.req.header('authorization')?.slice(7)
  const u = token ? await c.env.DB.prepare('SELECT u.id, u.name, u.email, u.role FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?').bind(token).first<User>() : null
  if (!u) return c.json({ error: 'Unauthorized' }, 401)
  c.set('user', u)
  await next()
})

const canTeach = (u: User) => u.role === 'instructor' || u.role === 'admin'

app.get('/api/me', (c) => c.json(c.get('user')))

app.get('/api/courses', async (c) => {
  const u = c.get('user')
  const { results } = await c.env.DB.prepare(
    `SELECT c.id, c.title, c.description, us.name AS instructor,
      (SELECT COUNT(*) FROM lessons WHERE course_id = c.id) AS lessons,
      EXISTS(SELECT 1 FROM enrollments WHERE user_id = ? AND course_id = c.id) AS enrolled,
      (SELECT COUNT(*) FROM progress p JOIN lessons l ON l.id = p.lesson_id WHERE p.user_id = ? AND l.course_id = c.id) AS done
     FROM courses c JOIN users us ON us.id = c.instructor_id ORDER BY c.id DESC`
  ).bind(u.id, u.id).all()
  return c.json(results)
})

app.post('/api/courses', async (c) => {
  const u = c.get('user')
  if (!canTeach(u)) return c.json({ error: 'Instructors only' }, 403)
  const { title, description } = await c.req.json()
  if (!title) return c.json({ error: 'Title required' }, 400)
  const r = await c.env.DB.prepare('INSERT INTO courses (title, description, instructor_id) VALUES (?, ?, ?)').bind(title, description || '', u.id).run()
  return c.json({ id: r.meta.last_row_id })
})

app.get('/api/courses/:id', async (c) => {
  const u = c.get('user'), id = Number(c.req.param('id')), db = c.env.DB
  const course = await db.prepare('SELECT c.*, us.name AS instructor FROM courses c JOIN users us ON us.id = c.instructor_id WHERE c.id = ?').bind(id).first<any>()
  if (!course) return c.json({ error: 'Not found' }, 404)
  const enrolled = !!(await db.prepare('SELECT 1 FROM enrollments WHERE user_id = ? AND course_id = ?').bind(u.id, id).first())
  const { results: lessons } = await db.prepare('SELECT id, title, content, video_url, EXISTS(SELECT 1 FROM progress WHERE user_id = ? AND lesson_id = lessons.id) AS done FROM lessons WHERE course_id = ? ORDER BY position, id').bind(u.id, id).all()
  const owner = u.id === course.instructor_id || u.role === 'admin'
  const visible = enrolled || owner // lesson bodies only for enrolled students and the owner
  return c.json({ ...course, enrolled, owner, lessons: lessons.map((l: any) => (visible ? l : { id: l.id, title: l.title, done: 0, locked: true })) })
})

app.post('/api/courses/:id/lessons', async (c) => {
  const u = c.get('user'), id = Number(c.req.param('id'))
  const course = await c.env.DB.prepare('SELECT instructor_id FROM courses WHERE id = ?').bind(id).first<any>()
  if (!course) return c.json({ error: 'Not found' }, 404)
  if (u.id !== course.instructor_id && u.role !== 'admin') return c.json({ error: 'Not your course' }, 403)
  const { title, content, video_url } = await c.req.json()
  if (!title) return c.json({ error: 'Title required' }, 400)
  const pos = await c.env.DB.prepare('SELECT COALESCE(MAX(position), 0) + 1 AS p FROM lessons WHERE course_id = ?').bind(id).first<{ p: number }>()
  await c.env.DB.prepare('INSERT INTO lessons (course_id, position, title, content, video_url) VALUES (?, ?, ?, ?, ?)').bind(id, pos?.p ?? 1, title, content || '', video_url || '').run()
  return c.json({ ok: true })
})

app.post('/api/courses/:id/enroll', async (c) => {
  await c.env.DB.prepare('INSERT OR IGNORE INTO enrollments (user_id, course_id) VALUES (?, ?)').bind(c.get('user').id, Number(c.req.param('id'))).run()
  return c.json({ ok: true })
})

app.post('/api/lessons/:id/complete', async (c) => {
  const u = c.get('user'), lid = Number(c.req.param('id'))
  const ok = await c.env.DB.prepare('SELECT 1 FROM lessons l JOIN enrollments e ON e.course_id = l.course_id WHERE l.id = ? AND e.user_id = ?').bind(lid, u.id).first()
  if (!ok) return c.json({ error: 'Enroll first' }, 403)
  await c.env.DB.prepare('INSERT OR IGNORE INTO progress (user_id, lesson_id) VALUES (?, ?)').bind(u.id, lid).run()
  return c.json({ ok: true })
})

app.get('/api/users', async (c) => {
  if (c.get('user').role !== 'admin') return c.json({ error: 'Admins only' }, 403)
  const { results } = await c.env.DB.prepare('SELECT id, name, email, role FROM users ORDER BY id').all()
  return c.json(results)
})

app.patch('/api/users/:id/role', async (c) => {
  if (c.get('user').role !== 'admin') return c.json({ error: 'Admins only' }, 403)
  const { role } = await c.req.json()
  if (!['student', 'instructor', 'admin'].includes(role)) return c.json({ error: 'Bad role' }, 400)
  await c.env.DB.prepare('UPDATE users SET role = ? WHERE id = ?').bind(role, Number(c.req.param('id'))).run()
  return c.json({ ok: true })
})

export default app
