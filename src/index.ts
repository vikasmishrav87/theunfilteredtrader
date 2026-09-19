import express from 'express'
import path from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express()

// Serve static assets from public directory
app.use(express.static(path.join(__dirname, '..', 'public')))

// Home route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'))
})

// Dedicated page routes
const dedicatedPages = [
  'about',
  'vip',
  'brokers',
  'syllabus',
  'premium',
  'indian-market',
  'fibonacci-group',
  'courses',
  'mentorship',
  'prop-firms',
  'reviews',
  'chat',
  'feedback',
  'contact'
]

dedicatedPages.forEach(page => {
  app.get(`/${page}`, (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'public', `${page}.html`))
  })
})

// Aliases for user convenience
app.get('/paid', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'premium.html'))
})
app.get('/ai-chat', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'chat.html'))
})
app.get('/suggestions', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'feedback.html'))
})

// Health check
app.get('/healthz', (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() })
})

export default app
