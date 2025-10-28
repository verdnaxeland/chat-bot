const path = require('path');
const http = require('http');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, param, validationResult } = require('express-validator');
const { Server } = require('socket.io');

dotenv.config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.CLIENT_ORIGIN ? process.env.CLIENT_ORIGIN.split(',') : '*',
    methods: ['GET', 'POST', 'PATCH', 'DELETE']
  }
});

const port = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me';
const TOKEN_EXPIRES_IN = process.env.TOKEN_EXPIRES_IN || '7d';

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

const poolPromise = createPool();

function asyncHandler(handler) {
  return (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
}

function signToken(userId) {
  return jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: TOKEN_EXPIRES_IN });
}

function formatUser(row) {
  return {
    id: row.id,
    username: row.username,
    email: row.email,
    avatarUrl: row.avatar_url,
    createdAt: row.created_at
  };
}

function formatChannelMessage(row) {
  return {
    id: row.id,
    channelId: row.channel_id,
    author: {
      id: row.author_id,
      username: row.username,
      avatarUrl: row.avatar_url
    },
    content: row.content,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    deleted: Boolean(row.deleted_at)
  };
}

function formatDirectMessage(row) {
  return {
    id: row.id,
    conversationId: row.conversation_id,
    author: {
      id: row.author_id,
      username: row.username,
      avatarUrl: row.avatar_url
    },
    content: row.content,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    deleted: Boolean(row.deleted_at)
  };
}

function generateInviteCode() {
  return crypto.randomBytes(5).toString('hex');
}

async function fetchServersForUser(userId, { includeChannels = false } = {}) {
  const pool = await poolPromise;
  const [serverRows] = await pool.execute(
    `SELECT s.id, s.name, s.icon_url, s.invite_code, s.created_at, sm.role
     FROM servers s
     INNER JOIN server_members sm ON sm.server_id = s.id
     WHERE sm.user_id = ?
     ORDER BY s.created_at ASC`,
    [userId]
  );

  if (!includeChannels || serverRows.length === 0) {
    return serverRows.map((server) => ({
      id: server.id,
      name: server.name,
      iconUrl: server.icon_url,
      inviteCode: server.invite_code,
      createdAt: server.created_at,
      role: server.role
    }));
  }

  const serverIds = serverRows.map((server) => server.id);
  const placeholders = serverIds.map(() => '?').join(',');
  const [channelRows] = await pool.query(
    `SELECT id, server_id, name, type, topic, created_at
     FROM channels
     WHERE server_id IN (${placeholders})
     ORDER BY created_at ASC`,
    serverIds
  );

  const channelsByServer = new Map();
  channelRows.forEach((channel) => {
    const list = channelsByServer.get(channel.server_id) || [];
    list.push({
      id: channel.id,
      name: channel.name,
      type: channel.type,
      topic: channel.topic,
      createdAt: channel.created_at
    });
    channelsByServer.set(channel.server_id, list);
  });

  return serverRows.map((server) => ({
    id: server.id,
    name: server.name,
    iconUrl: server.icon_url,
    inviteCode: server.invite_code,
    createdAt: server.created_at,
    role: server.role,
    channels: channelsByServer.get(server.id) || []
  }));
}

async function fetchDirectConversations(userId) {
  const pool = await poolPromise;

  // Passo 1: buscar conversas do usuário
  const [conversationRows] = await pool.execute(
    `SELECT dc.id, dc.created_at
     FROM direct_conversations dc
     WHERE dc.id IN (
       SELECT conversation_id FROM direct_participants WHERE user_id = ?
     )
     ORDER BY dc.created_at DESC`,
    [userId]
  );

  if (conversationRows.length === 0) {
    return [];
  }

  // Passo 2: buscar participantes de todas as conversas
  const conversationIds = conversationRows.map((row) => row.id);
  const placeholders = conversationIds.map(() => '?').join(',');
  const [participantRows] = await pool.query(
    `SELECT dp.conversation_id, u.id, u.username, u.avatar_url
     FROM direct_participants dp
     INNER JOIN users u ON u.id = dp.user_id
     WHERE dp.conversation_id IN (${placeholders})
     ORDER BY dp.conversation_id ASC, u.username ASC`,
    conversationIds
  );

  const participantsByConversation = new Map();
  participantRows.forEach((row) => {
    const list = participantsByConversation.get(row.conversation_id) || [];
    list.push({
      id: row.id,
      username: row.username,
      avatarUrl: row.avatar_url
    });
    participantsByConversation.set(row.conversation_id, list);
  });

  return conversationRows.map((row) => ({
    id: row.id,
    createdAt: row.created_at,
    participants: participantsByConversation.get(row.id) || []
  }));
}

async function fetchChannelMessageById(messageId) {
  const pool = await poolPromise;
  const [rows] = await pool.execute(
    `SELECT m.id, m.channel_id, m.content, m.created_at, m.updated_at, m.deleted_at,
            u.id AS author_id, u.username, u.avatar_url
     FROM channel_messages m
     INNER JOIN users u ON u.id = m.author_id
     WHERE m.id = ?`,
    [messageId]
  );
  return rows[0] ? formatChannelMessage(rows[0]) : null;
}

async function fetchDirectMessageById(messageId) {
  const pool = await poolPromise;
  const [rows] = await pool.execute(
    `SELECT m.id, m.conversation_id, m.content, m.created_at, m.updated_at, m.deleted_at,
            u.id AS author_id, u.username, u.avatar_url
     FROM direct_messages m
     INNER JOIN users u ON u.id = m.author_id
     WHERE m.id = ?`,
    [messageId]
  );
  return rows[0] ? formatDirectMessage(rows[0]) : null;
}

async function ensureServerMember(userId, serverId) {
  const pool = await poolPromise;
  const [rows] = await pool.execute(
    `SELECT server_id, user_id, role
     FROM server_members
     WHERE user_id = ? AND server_id = ?`,
    [userId, serverId]
  );
  return rows[0] || null;
}

async function ensureChannelAccess(userId, channelId) {
  const pool = await poolPromise;
  const [rows] = await pool.execute(
    `SELECT c.server_id, sm.role
     FROM channels c
     INNER JOIN server_members sm ON sm.server_id = c.server_id
     WHERE c.id = ? AND sm.user_id = ?`,
    [channelId, userId]
  );
  return rows[0] || null;
}

async function ensureConversationMember(userId, conversationId) {
  const pool = await poolPromise;
  const [rows] = await pool.execute(
    `SELECT conversation_id, user_id
     FROM direct_participants
     WHERE conversation_id = ? AND user_id = ?`,
    [conversationId, userId]
  );
  return rows[0] || null;
}

async function buildUserContext(userId) {
  const pool = await poolPromise;
  const [userRows] = await pool.execute(
    `SELECT id, username, email, avatar_url, created_at FROM users WHERE id = ?`,
    [userId]
  );

  if (!userRows.length) {
    return null;
  }

  const servers = await fetchServersForUser(userId, { includeChannels: true });
  const directConversations = await fetchDirectConversations(userId);
  const [friendRows] = await pool.execute(
    `SELECT fr.id, fr.status, fr.requester_id, fr.addressee_id, fr.created_at, fr.responded_at,
            ru.username AS requester_username,
            au.username AS addressee_username
     FROM friend_requests fr
     INNER JOIN users ru ON ru.id = fr.requester_id
     INNER JOIN users au ON au.id = fr.addressee_id
     WHERE fr.requester_id = ? OR fr.addressee_id = ?
     ORDER BY fr.created_at DESC`,
    [userId, userId]
  );

  const friends = {
    accepted: [],
    outgoing: [],
    incoming: [],
    declined: []
  };

  friendRows.forEach((row) => {
    const payload = {
      id: row.id,
      status: row.status,
      requester: { id: row.requester_id, username: row.requester_username },
      addressee: { id: row.addressee_id, username: row.addressee_username },
      createdAt: row.created_at,
      respondedAt: row.responded_at
    };

    if (row.status === 'accepted') {
      friends.accepted.push(payload);
    } else if (row.status === 'pending') {
      if (row.addressee_id === userId) {
        friends.incoming.push(payload);
      } else {
        friends.outgoing.push(payload);
      }
    } else {
      friends.declined.push(payload);
    }
  });

  return {
    user: formatUser(userRows[0]),
    servers,
    directConversations,
    friends
  };
}

async function authenticateRequest(req, res, next) {
  const header = req.headers.authorization;
  if (!header) {
    return res.status(401).json({ error: 'Token ausente' });
  }

  const [, token] = header.split(' ');

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const pool = await poolPromise;
    const [rows] = await pool.execute(
      `SELECT id, username, email, avatar_url, created_at FROM users WHERE id = ?`,
      [payload.sub]
    );

    if (!rows.length) {
      return res.status(401).json({ error: 'Usuário não encontrado' });
    }

    req.user = formatUser(rows[0]);
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Token inválido' });
  }
}

// Auth routes
app.post(
  '/api/auth/register',
  [
    body('username')
      .trim()
      .isLength({ min: 3, max: 32 })
      .matches(/^[A-Za-z0-9_]+$/)
      .withMessage('O nome de usuário deve conter apenas letras, números ou _'),
    body('email').isEmail().withMessage('E-mail inválido'),
    body('password').isLength({ min: 8 }).withMessage('A senha deve ter pelo menos 8 caracteres')
  ],
  handleValidationErrors,
  asyncHandler(async (req, res) => {
    const { username, email, password } = req.body;
    const pool = await poolPromise;

    const hash = await bcrypt.hash(password, 10);

    try {
      const [result] = await pool.execute(
        `INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)`,
        [username, email.toLowerCase(), hash]
      );

      const token = signToken(result.insertId);
      const context = await buildUserContext(result.insertId);

      res.status(201).json({ token, ...context });
    } catch (error) {
      if (error.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({ error: 'Nome de usuário ou e-mail já em uso' });
      }
      throw error;
    }
  })
);

app.post(
  '/api/auth/login',
  [
    body('identifier').trim().notEmpty().withMessage('Informe usuário ou e-mail'),
    body('password').notEmpty().withMessage('Informe a senha')
  ],
  handleValidationErrors,
  asyncHandler(async (req, res) => {
    const { identifier, password } = req.body;
    const pool = await poolPromise;

    const [rows] = await pool.execute(
      `SELECT id, username, email, password_hash, avatar_url, created_at
       FROM users
       WHERE username = ? OR email = ?`,
      [identifier, identifier.toLowerCase()]
    );

    if (!rows.length) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    const user = rows[0];
    const isValid = await bcrypt.compare(password, user.password_hash);

    if (!isValid) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    const token = signToken(user.id);
    const context = await buildUserContext(user.id);

    res.json({ token, ...context });
  })
);

app.get(
  '/api/auth/me',
  authenticateRequest,
  asyncHandler(async (req, res) => {
    const context = await buildUserContext(req.user.id);
    res.json(context);
  })
);

// Server routes
app.get(
  '/api/servers',
  authenticateRequest,
  asyncHandler(async (req, res) => {
    const servers = await fetchServersForUser(req.user.id, { includeChannels: true });
    res.json(servers);
  })
);

app.post(
  '/api/servers',
  authenticateRequest,
  [
    body('name').trim().isLength({ min: 3, max: 100 }).withMessage('Nome inválido'),
    body('iconUrl').optional({ checkFalsy: true }).isURL().withMessage('URL do ícone inválida')
  ],
  handleValidationErrors,
  asyncHandler(async (req, res) => {
    const { name, iconUrl } = req.body;
    const pool = await poolPromise;
    const inviteCode = generateInviteCode();

    const connection = await pool.getConnection();

    try {
      await connection.beginTransaction();

      const [serverResult] = await connection.execute(
        `INSERT INTO servers (name, icon_url, owner_id, invite_code) VALUES (?, ?, ?, ?)`,
        [name, iconUrl || null, req.user.id, inviteCode]
      );

      const serverId = serverResult.insertId;

      await connection.execute(
        `INSERT INTO server_members (server_id, user_id, role) VALUES (?, ?, 'owner')`,
        [serverId, req.user.id]
      );

      await connection.execute(
        `INSERT INTO channels (server_id, name, type) VALUES (?, 'geral', 'text')`,
        [serverId]
      );

      await connection.commit();

      const servers = await fetchServersForUser(req.user.id, { includeChannels: true });
      const createdServer = servers.find((item) => item.id === serverId);

      io.to(`user:${req.user.id}`).emit('servers:created', createdServer);

      res.status(201).json(createdServer);
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  })
);

app.get(
  '/api/servers/:serverId',
  authenticateRequest,
  asyncHandler(async (req, res) => {
    const serverId = Number(req.params.serverId);
    const membership = await ensureServerMember(req.user.id, serverId);

    if (!membership) {
      return res.status(403).json({ error: 'Acesso negado a este servidor' });
    }

    const servers = await fetchServersForUser(req.user.id, { includeChannels: true });
    const server = servers.find((item) => item.id === serverId);

    res.json(server);
  })
);

app.post(
  '/api/servers/:serverId/channels',
  authenticateRequest,
  [
    param('serverId').isInt({ gt: 0 }),
    body('name').trim().isLength({ min: 2, max: 100 }).withMessage('Nome inválido'),
    body('type').optional().isIn(['text', 'voice']).withMessage('Tipo inválido'),
    body('topic').optional({ checkFalsy: true }).isLength({ max: 255 })
  ],
  handleValidationErrors,
  asyncHandler(async (req, res) => {
    const serverId = Number(req.params.serverId);
    const { name, type = 'text', topic } = req.body;

    const membership = await ensureServerMember(req.user.id, serverId);

    if (!membership) {
      return res.status(403).json({ error: 'Acesso negado a este servidor' });
    }

    const pool = await poolPromise;

    try {
      const [result] = await pool.execute(
        `INSERT INTO channels (server_id, name, type, topic) VALUES (?, ?, ?, ?)`,
        [serverId, name, type, topic || null]
      );

      const channel = {
        id: result.insertId,
        serverId,
        name,
        type,
        topic: topic || null
      };

      io.to(`server:${serverId}`).emit('channels:created', channel);

      res.status(201).json(channel);
    } catch (error) {
      if (error.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({ error: 'Já existe um canal com este nome' });
      }
      throw error;
    }
  })
);

app.get(
  '/api/servers/:serverId/channels',
  authenticateRequest,
  asyncHandler(async (req, res) => {
    const serverId = Number(req.params.serverId);
    const membership = await ensureServerMember(req.user.id, serverId);

    if (!membership) {
      return res.status(403).json({ error: 'Acesso negado a este servidor' });
    }

    const pool = await poolPromise;
    const [rows] = await pool.execute(
      `SELECT id, name, type, topic, created_at FROM channels WHERE server_id = ? ORDER BY created_at ASC`,
      [serverId]
    );

    res.json(rows.map((channel) => ({
      id: channel.id,
      name: channel.name,
      type: channel.type,
      topic: channel.topic,
      createdAt: channel.created_at
    })));
  })
);

app.post(
  '/api/invites/:code',
  authenticateRequest,
  asyncHandler(async (req, res) => {
    const inviteCode = req.params.code;
    const pool = await poolPromise;

    const [serverRows] = await pool.execute(
      `SELECT id FROM servers WHERE invite_code = ?`,
      [inviteCode]
    );

    if (!serverRows.length) {
      return res.status(404).json({ error: 'Convite inválido' });
    }

    const serverId = serverRows[0].id;

    const membership = await ensureServerMember(req.user.id, serverId);

    if (membership) {
      return res.status(200).json({ message: 'Você já participa deste servidor' });
    }

    await pool.execute(
      `INSERT INTO server_members (server_id, user_id, role) VALUES (?, ?, 'member')`,
      [serverId, req.user.id]
    );

    const servers = await fetchServersForUser(req.user.id, { includeChannels: true });
    const server = servers.find((item) => item.id === serverId);

    io.to(`server:${serverId}`).emit('server:member-joined', {
      serverId,
      user: req.user
    });

    io.to(`user:${req.user.id}`).emit('servers:joined', server);

    res.status(201).json(server);
  })
);

// Channel messages
app.get(
  '/api/channels/:channelId/messages',
  authenticateRequest,
  asyncHandler(async (req, res) => {
    const channelId = Number(req.params.channelId);
    const access = await ensureChannelAccess(req.user.id, channelId);

    if (!access) {
      return res.status(403).json({ error: 'Acesso negado a este canal' });
    }

    const pool = await poolPromise;
    const [rows] = await pool.execute(
      `SELECT m.id, m.channel_id, m.content, m.created_at, m.updated_at, m.deleted_at,
              u.id AS author_id, u.username, u.avatar_url
       FROM channel_messages m
       INNER JOIN users u ON u.id = m.author_id
       WHERE m.channel_id = ?
       ORDER BY m.created_at ASC
       LIMIT 500`,
      [channelId]
    );

    res.json(rows.map(formatChannelMessage));
  })
);

app.post(
  '/api/channels/:channelId/messages',
  authenticateRequest,
  [body('content').trim().isLength({ min: 1, max: 4000 }).withMessage('Mensagem inválida')],
  handleValidationErrors,
  asyncHandler(async (req, res) => {
    const channelId = Number(req.params.channelId);
    const { content } = req.body;
    const access = await ensureChannelAccess(req.user.id, channelId);

    if (!access) {
      return res.status(403).json({ error: 'Acesso negado a este canal' });
    }

    const pool = await poolPromise;
    const [result] = await pool.execute(
      `INSERT INTO channel_messages (channel_id, author_id, content) VALUES (?, ?, ?)`,
      [channelId, req.user.id, content]
    );

    const message = await fetchChannelMessageById(result.insertId);

    io.to(`channel:${channelId}`).emit('channel:message', message);

    res.status(201).json(message);
  })
);

app.patch(
  '/api/channels/:channelId/messages/:messageId',
  authenticateRequest,
  [body('content').trim().isLength({ min: 1, max: 4000 }).withMessage('Mensagem inválida')],
  handleValidationErrors,
  asyncHandler(async (req, res) => {
    const channelId = Number(req.params.channelId);
    const messageId = Number(req.params.messageId);
    const { content } = req.body;

    const access = await ensureChannelAccess(req.user.id, channelId);
    if (!access) {
      return res.status(403).json({ error: 'Acesso negado a este canal' });
    }

    const pool = await poolPromise;
    const [result] = await pool.execute(
      `UPDATE channel_messages
       SET content = ?, updated_at = NOW()
       WHERE id = ? AND author_id = ? AND channel_id = ? AND deleted_at IS NULL`,
      [content, messageId, req.user.id, channelId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Mensagem não encontrada' });
    }

    const message = await fetchChannelMessageById(messageId);

    io.to(`channel:${channelId}`).emit('channel:message:update', message);

    res.json(message);
  })
);

app.delete(
  '/api/channels/:channelId/messages/:messageId',
  authenticateRequest,
  asyncHandler(async (req, res) => {
    const channelId = Number(req.params.channelId);
    const messageId = Number(req.params.messageId);

    const access = await ensureChannelAccess(req.user.id, channelId);
    if (!access) {
      return res.status(403).json({ error: 'Acesso negado a este canal' });
    }

    const pool = await poolPromise;
    const [result] = await pool.execute(
      `UPDATE channel_messages
       SET content = '', deleted_at = NOW(), updated_at = NOW()
       WHERE id = ? AND author_id = ? AND channel_id = ? AND deleted_at IS NULL`,
      [messageId, req.user.id, channelId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Mensagem não encontrada' });
    }

    io.to(`channel:${channelId}`).emit('channel:message:deleted', {
      id: messageId,
      channelId
    });

    res.status(204).send();
  })
);

// Friend requests
app.get(
  '/api/friends',
  authenticateRequest,
  asyncHandler(async (req, res) => {
    const context = await buildUserContext(req.user.id);
    res.json(context.friends);
  })
);

app.post(
  '/api/friends/requests',
  authenticateRequest,
  [body('username').trim().notEmpty().withMessage('Informe o usuário')],
  handleValidationErrors,
  asyncHandler(async (req, res) => {
    const { username } = req.body;
    const pool = await poolPromise;

    const [userRows] = await pool.execute(
      `SELECT id, username FROM users WHERE username = ?`,
      [username]
    );

    if (!userRows.length) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    const target = userRows[0];

    if (target.id === req.user.id) {
      return res.status(400).json({ error: 'Você não pode adicionar a si mesmo' });
    }

    const [existingRows] = await pool.execute(
      `SELECT id, status FROM friend_requests
       WHERE (requester_id = ? AND addressee_id = ?)
          OR (requester_id = ? AND addressee_id = ?)`,
      [req.user.id, target.id, target.id, req.user.id]
    );

    if (existingRows.length) {
      const existing = existingRows[0];
      if (existing.status === 'pending') {
        return res.status(409).json({ error: 'Já existe um convite pendente' });
      }
      await pool.execute(
        `UPDATE friend_requests
         SET requester_id = ?, addressee_id = ?, status = 'pending', created_at = NOW(), responded_at = NULL
         WHERE id = ?`,
        [req.user.id, target.id, existing.id]
      );
      return res.status(201).json({ message: 'Convite reenviado' });
    }

    await pool.execute(
      `INSERT INTO friend_requests (requester_id, addressee_id) VALUES (?, ?)`,
      [req.user.id, target.id]
    );

    io.to(`user:${target.id}`).emit('friends:request', {
      requester: req.user,
      addressee: target
    });

    res.status(201).json({ message: 'Convite enviado' });
  })
);

app.post(
  '/api/friends/requests/:requestId/respond',
  authenticateRequest,
  [body('action').isIn(['accept', 'decline', 'block']).withMessage('Ação inválida')],
  handleValidationErrors,
  asyncHandler(async (req, res) => {
    const requestId = Number(req.params.requestId);
    const { action } = req.body;
    const pool = await poolPromise;

    const [rows] = await pool.execute(
      `SELECT id, requester_id, addressee_id, status FROM friend_requests WHERE id = ?`,
      [requestId]
    );

    if (!rows.length) {
      return res.status(404).json({ error: 'Solicitação não encontrada' });
    }

    const request = rows[0];

    if (request.addressee_id !== req.user.id) {
      return res.status(403).json({ error: 'Você não pode responder a esta solicitação' });
    }

    let status = 'declined';
    if (action === 'accept') {
      status = 'accepted';
    } else if (action === 'block') {
      status = 'blocked';
    }

    await pool.execute(
      `UPDATE friend_requests SET status = ?, responded_at = NOW() WHERE id = ?`,
      [status, requestId]
    );

    io.to(`user:${request.requester_id}`).emit('friends:updated', { requestId, status });

    res.json({ requestId, status });
  })
);

// Direct conversations
app.get(
  '/api/dms',
  authenticateRequest,
  asyncHandler(async (req, res) => {
    const conversations = await fetchDirectConversations(req.user.id);
    res.json(conversations);
  })
);

app.post(
  '/api/dms',
  authenticateRequest,
  [body('userId').isInt({ gt: 0 }).withMessage('Usuário inválido')],
  handleValidationErrors,
  asyncHandler(async (req, res) => {
    const { userId } = req.body;

    if (userId === req.user.id) {
      return res.status(400).json({ error: 'Não é possível criar conversa consigo mesmo' });
    }

    const pairKey = [req.user.id, userId].sort((a, b) => a - b).join(':');
    const pool = await poolPromise;

    const [existingRows] = await pool.execute(
      `SELECT id FROM direct_conversations WHERE unique_key = ?`,
      [pairKey]
    );

    if (existingRows.length) {
      const conversation = (await fetchDirectConversations(req.user.id)).find(
        (item) => item.id === existingRows[0].id
      );
      return res.json(conversation);
    }

    const connection = await pool.getConnection();

    try {
      await connection.beginTransaction();

      const [conversationResult] = await connection.execute(
        `INSERT INTO direct_conversations (unique_key) VALUES (?)`,
        [pairKey]
      );

      const conversationId = conversationResult.insertId;

      await connection.execute(
        `INSERT INTO direct_participants (conversation_id, user_id) VALUES (?, ?), (?, ?)`,
        [conversationId, req.user.id, conversationId, userId]
      );

      await connection.commit();

      const conversation = (await fetchDirectConversations(req.user.id)).find(
        (item) => item.id === conversationId
      );

      io.to(`user:${userId}`).emit('dms:created', conversation);

      res.status(201).json(conversation);
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  })
);

app.get(
  '/api/dms/:conversationId/messages',
  authenticateRequest,
  asyncHandler(async (req, res) => {
    const conversationId = Number(req.params.conversationId);
    const membership = await ensureConversationMember(req.user.id, conversationId);

    if (!membership) {
      return res.status(403).json({ error: 'Conversa não encontrada' });
    }

    const pool = await poolPromise;
    const [rows] = await pool.execute(
      `SELECT m.id, m.conversation_id, m.content, m.created_at, m.updated_at, m.deleted_at,
              u.id AS author_id, u.username, u.avatar_url
       FROM direct_messages m
       INNER JOIN users u ON u.id = m.author_id
       WHERE m.conversation_id = ?
       ORDER BY m.created_at ASC
       LIMIT 500`,
      [conversationId]
    );

    res.json(rows.map(formatDirectMessage));
  })
);

app.post(
  '/api/dms/:conversationId/messages',
  authenticateRequest,
  [body('content').trim().isLength({ min: 1, max: 4000 }).withMessage('Mensagem inválida')],
  handleValidationErrors,
  asyncHandler(async (req, res) => {
    const conversationId = Number(req.params.conversationId);
    theContent = req.body.content; // prevent shadowing in some bundlers? still ok
    const { content } = { content: theContent };

    const membership = await ensureConversationMember(req.user.id, conversationId);

    if (!membership) {
      return res.status(403).json({ error: 'Conversa não encontrada' });
    }

    const pool = await poolPromise;
    const [result] = await pool.execute(
      `INSERT INTO direct_messages (conversation_id, author_id, content) VALUES (?, ?, ?)`,
      [conversationId, req.user.id, content]
    );

    const message = await fetchDirectMessageById(result.insertId);

    io.to(`dm:${conversationId}`).emit('dm:message', message);

    res.status(201).json(message);
  })
);

app.patch(
  '/api/dms/:conversationId/messages/:messageId',
  authenticateRequest,
  [body('content').trim().isLength({ min: 1, max: 4000 }).withMessage('Mensagem inválida')],
  handleValidationErrors,
  asyncHandler(async (req, res) => {
    const conversationId = Number(req.params.conversationId);
    const messageId = Number(req.params.messageId);
    const { content } = req.body;
    const membership = await ensureConversationMember(req.user.id, conversationId);

    if (!membership) {
      return res.status(403).json({ error: 'Conversa não encontrada' });
    }

    const pool = await poolPromise;
    const [result] = await pool.execute(
      `UPDATE direct_messages
       SET content = ?, updated_at = NOW()
       WHERE id = ? AND author_id = ? AND conversation_id = ? AND deleted_at IS NULL`,
      [content, messageId, req.user.id, conversationId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Mensagem não encontrada' });
    }

    const message = await fetchDirectMessageById(messageId);

    io.to(`dm:${conversationId}`).emit('dm:message:update', message);

    res.json(message);
  })
);

app.delete(
  '/api/dms/:conversationId/messages/:messageId',
  authenticateRequest,
  asyncHandler(async (req, res) => {
    const conversationId = Number(req.params.conversationId);
    const messageId = Number(req.params.messageId);
    const membership = await ensureConversationMember(req.user.id, conversationId);

    if (!membership) {
      return res.status(403).json({ error: 'Conversa não encontrada' });
    }

    const pool = await poolPromise;
    const [result] = await pool.execute(
      `UPDATE direct_messages
       SET content = '', deleted_at = NOW(), updated_at = NOW()
       WHERE id = ? AND author_id = ? AND conversation_id = ? AND deleted_at IS NULL`,
      [messageId, req.user.id, conversationId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Mensagem não encontrada' });
    }

    io.to(`dm:${conversationId}`).emit('dm:message:deleted', {
      id: messageId,
      conversationId
    });

    res.status(204).send();
  })
);

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

io.use(async (socket, next) => {
  const token = socket.handshake.auth?.token || socket.handshake.query?.token;

  if (!token) {
    return next(new Error('Unauthorized'));
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const pool = await poolPromise;
    const [rows] = await pool.execute(
      `SELECT id, username FROM users WHERE id = ?`,
      [payload.sub]
    );

    if (!rows.length) {
      return next(new Error('Unauthorized'));
    }

    socket.user = { id: rows[0].id, username: rows[0].username };
    next();
  } catch (error) {
    next(new Error('Unauthorized'));
  }
});

io.on('connection', async (socket) => {
  socket.join(`user:${socket.user.id}`);

  try {
    const servers = await fetchServersForUser(socket.user.id, { includeChannels: false });
    servers.forEach((server) => {
      socket.join(`server:${server.id}`);
    });

    const conversations = await fetchDirectConversations(socket.user.id);
    conversations.forEach((conversation) => {
      socket.join(`dm:${conversation.id}`);
    });
  } catch (error) {
    console.error('Failed to preload socket rooms', error);
  }

  socket.on('joinChannel', async ({ channelId }) => {
    if (!channelId) return;
    const access = await ensureChannelAccess(socket.user.id, Number(channelId));
    if (access) {
      socket.join(`channel:${channelId}`);
    }
  });

  socket.on('leaveChannel', ({ channelId }) => {
    if (!channelId) return;
    socket.leave(`channel:${channelId}`);
  });

  socket.on('joinDm', async ({ conversationId }) => {
    if (!conversationId) return;
    const membership = await ensureConversationMember(socket.user.id, Number(conversationId));
    if (membership) {
      socket.join(`dm:${conversationId}`);
    }
  });

  socket.on('leaveDm', ({ conversationId }) => {
    if (!conversationId) return;
    socket.leave(`dm:${conversationId}`);
  });
});

app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) {
    return next(err);
  }
  res.status(err.status || 500).json({ error: err.message || 'Erro interno do servidor' });
});

server.listen(port, () => {
  console.log(`Servidor escutando na porta ${port}`);
});
