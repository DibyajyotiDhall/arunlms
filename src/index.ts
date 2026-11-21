import { Hono } from 'hono'

// TEST MODE: all data lives in memory (no database). It resets when the Worker restarts.
type User = { id: number; name: string; email: string; role: string }
type Rec = User & { salt: string; hash: string }
type Course = { id: number; title: string; description: string; instructor_id: number }
type Lesson = { id: number; course_id: number; title: string; content: string; video_url: string }

const users: Rec[] = []
const sessions = new Map<string, number>()
const courses: Course[] = []
const lessons: Lesson[] = []
const enrollments = new Set<string>() // "userId:courseId"
const progress = new Set<string>() // "userId:lessonId"
let nextId = 1

const app = new Hono<{ Variables: { user: User } }>()
const enc = new TextEncoder()
const hex = (b: ArrayBuffer | Uint8Array) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('')
const rand = (n: number) => hex(crypto.getRandomValues(new Uint8Array(n)))
const pub = (u: Rec): User => ({ id: u.id, name: u.name, email: u.email, role: u.role })

async function hashPw(pw: string, salt: string) {
  const key = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits'])
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash: 'SHA-256' }, key, 256))
}

function newSession(userId: number) {
  const token = rand(32)
  sessions.set(token, userId)
  return token
}

app.post('/api/signup', async (c) => {
  const { name, email, password } = await c.req.json()
  if (!name || !email || !password || password.length < 8) return c.json({ error: 'Name, email and a password of 8+ characters are required' }, 400)
  if (users.some((u) => u.email === email.toLowerCase())) return c.json({ error: 'Email already registered' }, 409)
  const salt = rand(16)
  const u: Rec = { id: nextId++, name, email: email.toLowerCase(), salt, hash: await hashPw(password, salt), role: users.length === 0 ? 'admin' : 'student' }
  users.push(u)
  return c.json({ token: newSession(u.id), user: pub(u) })
})

app.post('/api/login', async (c) => {
  const { email, password } = await c.req.json()
  const u = users.find((x) => x.email === String(email || '').toLowerCase())
  if (!u || (await hashPw(String(password || ''), u.salt)) !== u.hash) return c.json({ error: 'Invalid email or password' }, 401)
  return c.json({ token: newSession(u.id), user: pub(u) })
})

app.use('/api/*', async (c, next) => {
  const token = c.req.header('authorization')?.slice(7)
  const u = token ? users.find((x) => x.id === sessions.get(token)) : undefined
  if (!u) return c.json({ error: 'Unauthorized' }, 401)
  c.set('user', pub(u))
  await next()
})

const canTeach = (u: User) => u.role === 'instructor' || u.role === 'admin'
const nameOf = (id: number) => users.find((u) => u.id === id)?.name ?? ''

app.get('/api/me', (c) => c.json(c.get('user')))

app.get('/api/courses', (c) => {
  const u = c.get('user')
  return c.json(
    [...courses].reverse().map((k) => {
      const ls = lessons.filter((l) => l.course_id === k.id)
      return { id: k.id, title: k.title, description: k.description, instructor: nameOf(k.instructor_id), lessons: ls.length, enrolled: enrollments.has(`${u.id}:${k.id}`), done: ls.filter((l) => progress.has(`${u.id}:${l.id}`)).length }
    })
  )
})

app.post('/api/courses', async (c) => {
  const u = c.get('user')
  if (!canTeach(u)) return c.json({ error: 'Instructors only' }, 403)
  const { title, description } = await c.req.json()
  if (!title) return c.json({ error: 'Title required' }, 400)
  const k: Course = { id: nextId++, title, description: description || '', instructor_id: u.id }
  courses.push(k)
  return c.json({ id: k.id })
})

app.get('/api/courses/:id', (c) => {
  const u = c.get('user'), id = Number(c.req.param('id'))
  const k = courses.find((x) => x.id === id)
  if (!k) return c.json({ error: 'Not found' }, 404)
  const enrolled = enrollments.has(`${u.id}:${id}`)
  const owner = u.id === k.instructor_id || u.role === 'admin'
  const visible = enrolled || owner // lesson bodies only for enrolled students and the owner
  const ls = lessons.filter((l) => l.course_id === id).map((l) => {
    const done = progress.has(`${u.id}:${l.id}`) ? 1 : 0
    return visible ? { id: l.id, title: l.title, content: l.content, video_url: l.video_url, done } : { id: l.id, title: l.title, done: 0, locked: true }
  })
  return c.json({ ...k, instructor: nameOf(k.instructor_id), enrolled, owner, lessons: ls })
})

app.post('/api/courses/:id/lessons', async (c) => {
  const u = c.get('user'), id = Number(c.req.param('id'))
  const k = courses.find((x) => x.id === id)
  if (!k) return c.json({ error: 'Not found' }, 404)
  if (u.id !== k.instructor_id && u.role !== 'admin') return c.json({ error: 'Not your course' }, 403)
  const { title, content, video_url } = await c.req.json()
  if (!title) return c.json({ error: 'Title required' }, 400)
  lessons.push({ id: nextId++, course_id: id, title, content: content || '', video_url: video_url || '' })
  return c.json({ ok: true })
})

app.post('/api/courses/:id/enroll', (c) => {
  const id = Number(c.req.param('id'))
  if (!courses.some((k) => k.id === id)) return c.json({ error: 'Not found' }, 404)
  enrollments.add(`${c.get('user').id}:${id}`)
  return c.json({ ok: true })
})

app.post('/api/lessons/:id/complete', (c) => {
  const u = c.get('user'), lid = Number(c.req.param('id'))
  const l = lessons.find((x) => x.id === lid)
  if (!l || !enrollments.has(`${u.id}:${l.course_id}`)) return c.json({ error: 'Enroll first' }, 403)
  progress.add(`${u.id}:${lid}`)
  return c.json({ ok: true })
})

app.get('/api/users', (c) => {
  if (c.get('user').role !== 'admin') return c.json({ error: 'Admins only' }, 403)
  return c.json(users.map(pub))
})

app.patch('/api/users/:id/role', async (c) => {
  if (c.get('user').role !== 'admin') return c.json({ error: 'Admins only' }, 403)
  const { role } = await c.req.json()
  if (!['student', 'instructor', 'admin'].includes(role)) return c.json({ error: 'Bad role' }, 400)
  const u = users.find((x) => x.id === Number(c.req.param('id')))
  if (u) u.role = role
  return c.json({ ok: true })
})

export default app
