# Chatbot Node.js + MySQL

Aplicação simples de chatbot construída com Node.js (Express) e MySQL com uma interface web em HTML.

## Pré-requisitos

- Node.js 18+
- MySQL 8+

## Configuração

1. Instale as dependências:

   ```bash
   npm install
   ```

2. Copie o arquivo `.env.example` para `.env` e ajuste as variáveis conforme o seu ambiente.

   ```bash
   cp .env.example .env
   ```

3. Execute o script SQL para criar o banco de dados e a tabela de mensagens:

   ```bash
   mysql -u seu_usuario -p < db/schema.sql
   ```

4. Inicie o servidor em modo desenvolvimento (com hot reload) ou produção:

   ```bash
   npm run dev
   # ou
   npm start
   ```

A aplicação estará disponível em `http://localhost:3000`.

## Estrutura de pastas

```
.
├── db
│   └── schema.sql
├── public
│   └── index.html
├── server.js
├── package.json
└── README.md
```

## API

- `GET /api/messages`: retorna todas as mensagens armazenadas.
- `POST /api/messages`: recebe `{ author, content }` e salva uma nova mensagem.

## Front-end

A pasta `public` contém um HTML com um layout simples para enviar e visualizar mensagens.
