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

function generateBotReply(message = '') {
  const normalized = message.toLowerCase();
  if (!normalized.trim()) {
    return 'Poderia repetir? Não entendi sua mensagem.';
  }

  if (/(ol[aá]|oi|bom dia|boa tarde|boa noite)/.test(normalized)) {
    return 'Olá! Como posso ajudar você hoje?';
  }

  if (/(ajuda|help|socorro)/.test(normalized)) {
    return 'Claro! Conte-me um pouco mais sobre o que você precisa e verei como ajudar.';
  }

  if (/(obrigad|valeu|thanks)/.test(normalized)) {
    return 'De nada! Se precisar de mais alguma coisa, é só falar 😊';
  }

  if (/(tchau|até logo|até mais)/.test(normalized)) {
    return 'Até logo! Foi um prazer conversar com você.';
  }

  return `Você disse: "${message}". Ainda estou aprendendo, mas quero te ajudar!`;
}

app.post('/api/messages', async (req, res) => {
  const { author, content } = req.body;

  if (!author || !content) {
    return res.status(400).json({ error: 'Author and content are required' });
  }

  let connection;

  try {
    const pool = await poolPromise;
    connection = await pool.getConnection();
    await connection.beginTransaction();

    const [userResult] = await connection.execute(
      'INSERT INTO messages (author, content) VALUES (?, ?)',
      [author.substring(0, 50), content.substring(0, 500)]
    );

    const botContent = generateBotReply(content).substring(0, 500);

    const [botResult] = await connection.execute(
      'INSERT INTO messages (author, content) VALUES (?, ?)',
      ['Bot', botContent]
    );

    const [[userMessage]] = await connection.execute(
      'SELECT id, author, content, created_at FROM messages WHERE id = ?',
      [userResult.insertId]
    );

    const [[botMessage]] = await connection.execute(
      'SELECT id, author, content, created_at FROM messages WHERE id = ?',
      [botResult.insertId]
    );

    await connection.commit();

    res.status(201).json({ user: userMessage, bot: botMessage });
  } catch (error) {
    if (connection) {
      await connection.rollback();
    }
    console.error('Failed to save message', error);
    res.status(500).json({ error: 'Unable to save message' });
  } finally {
    if (connection) {
      connection.release();
    }
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
