# MySQL Cord

Uma plataforma de chat em tempo real inspirada no Discord, construída com Node.js, Express, Socket.IO e MySQL. A aplicação oferece autenticação com JWT, gerenciamento de servidores, canais, mensagens diretas, convites e sistema de amizade – tudo persistido em MySQL.

## Principais funcionalidades

- Cadastro e login com hash de senha (bcrypt) e tokens JWT.
- Criação de servidores com código de convite único e canal `#geral` automático.
- Gerenciamento de canais por servidor (texto e voz, com suporte a tópicos).
- Troca de mensagens em tempo real via Socket.IO (edição e exclusão inclusas).
- Sistema de amizade com convites, aceite/recusa e bloqueio.
- Mensagens diretas entre usuários com histórico persistente.
- Front-end responsivo em HTML/CSS/JS puro com layout semelhante ao Discord.

## Pré-requisitos

- Node.js 18+
- MySQL 8+

## Configuração

1. Instale as dependências:

   ```bash
   npm install
   ```

2. Copie o arquivo `.env.example` para `.env` e ajuste as variáveis conforme o seu ambiente (porta, credenciais do banco, segredo JWT etc.).

   ```bash
   cp .env.example .env
   ```

3. Crie o banco e as tabelas executando o script SQL:

   ```bash
   mysql -u seu_usuario -p < db/schema.sql
   ```

4. Inicie o servidor:

   ```bash
   npm run dev   # nodemon
   # ou
   npm start
   ```

A aplicação ficará disponível em `http://localhost:3000`.

## Estrutura de pastas

```
.
├── db
│   └── schema.sql          # Script de criação das tabelas
├── public
│   └── index.html          # Front-end com layout tipo Discord
├── server.js               # Servidor Express + Socket.IO + rotas REST
├── package.json
└── README.md
```

## Endpoints principais

### Autenticação
- `POST /api/auth/register` – cria um novo usuário.
- `POST /api/auth/login` – autentica via usuário/e-mail + senha.
- `GET /api/auth/me` – retorna contexto completo do usuário autenticado.

### Servidores e canais
- `GET /api/servers` – lista servidores e canais do usuário.
- `POST /api/servers` – cria um novo servidor.
- `POST /api/servers/:serverId/channels` – cria um novo canal no servidor.
- `POST /api/invites/:code` – ingressa em um servidor via código de convite.

### Mensagens em canais
- `GET /api/channels/:channelId/messages`
- `POST /api/channels/:channelId/messages`
- `PATCH /api/channels/:channelId/messages/:messageId`
- `DELETE /api/channels/:channelId/messages/:messageId`

### Amigos e mensagens diretas
- `GET /api/friends` – retorna convites pendentes e amigos.
- `POST /api/friends/requests` – envia convite de amizade.
- `POST /api/friends/requests/:requestId/respond` – aceita, recusa ou bloqueia.
- `GET /api/dms` – lista conversas diretas.
- `POST /api/dms` – inicia/recupera conversa direta com outro usuário.
- `GET /api/dms/:conversationId/messages`
- `POST /api/dms/:conversationId/messages`
- `PATCH /api/dms/:conversationId/messages/:messageId`
- `DELETE /api/dms/:conversationId/messages/:messageId`

## Ambiente WebSocket

O Socket.IO é inicializado com autenticação via token JWT (enviado no `handshake`). Eventos disparados pelo servidor incluem:

- `channel:message`, `channel:message:update`, `channel:message:deleted`
- `dm:message`, `dm:message:update`, `dm:message:deleted`
- `servers:created`, `servers:joined`, `channels:created`
- `friends:request`, `friends:updated`, `dms:created`

O front-end consome esses eventos para atualizar a interface em tempo real.

## Desenvolvimento

O projeto utiliza apenas Node.js e front-end vanilla, facilitando extensões para recursos adicionais como permissões avançadas, upload de arquivos ou notificações push.
