const path = require('path');
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const mysql = require('mysql2/promise');

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

async function createPool() {
  const {
    DB_HOST = 'localhost',
    DB_PORT = '3306',
    DB_USER = 'root',
    DB_PASSWORD = '',
    DB_NAME = 'chatbot'
  } = process.env;

  return mysql.createPool({
    host: DB_HOST,
    port: Number(DB_PORT),
    user: DB_USER,
    password: DB_PASSWORD,
    database: DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  });
}

let poolPromise = createPool();

app.get('/api/messages', async (req, res) => {
  try {
    const pool = await poolPromise;
    const [rows] = await pool.query(
      'SELECT id, author, content, created_at FROM messages ORDER BY created_at ASC'
    );
    res.json(rows);
  } catch (error) {
    console.error('Failed to fetch messages', error);
    res.status(500).json({ error: 'Unable to fetch messages' });
  }
});

app.post('/api/messages', async (req, res) => {
  const { author, content } = req.body;

  if (!author || !content) {
    return res.status(400).json({ error: 'Author and content are required' });
  }

  try {
    const pool = await poolPromise;
    const [result] = await pool.execute(
      'INSERT INTO messages (author, content) VALUES (?, ?)',
      [author.substring(0, 50), content.substring(0, 500)]
    );

    const [rows] = await pool.execute(
      'SELECT id, author, content, created_at FROM messages WHERE id = ?',
      [result.insertId]
    );

    res.status(201).json(rows[0]);
  } catch (error) {
    console.error('Failed to save message', error);
    res.status(500).json({ error: 'Unable to save message' });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
