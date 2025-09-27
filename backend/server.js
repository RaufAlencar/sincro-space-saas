// server.js - Versão FINAL (Service Account OK)
// Autenticação com conta de serviço sincro-ai-novo

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const { Client } = require('whatsapp-web.js');
const qrcode = require('qrcode');
const { VertexAI } = require('@google-cloud/vertexai');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');

const app = express();
const PORT = process.env.PORT || 10000;

app.use(express.json());

// Configuração de CORS
const corsOptions = {
  origin: process.env.FRONTEND_URL,
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// Configuração do banco (Supabase)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
});

async function testDBConnection() {
  try {
    await pool.query('SELECT NOW()');
    console.log('[DB] Conexão com o banco de dados PostgreSQL bem-sucedida!');
  } catch (error) {
    console.error('[ERRO DB] Não foi possível conectar ao banco de dados:', error);
  }
}
testDBConnection();

// Gerenciamento de sessões WhatsApp
const sessions = new Map();

// ----------------- INICIALIZAÇÃO VERTEX AI -----------------
const vertex_ai = new VertexAI({
  project: process.env.GOOGLE_PROJECT_ID, // "sincro-ai-novo"
  location: 'us-central1',
  credentials: JSON.parse(process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON)
});

const model = vertex_ai.getGenerativeModel({
  model: 'gemini-1.5-flash-latest',
});

// ----------------- GOOGLE OAUTH -----------------
const oAuth2Client = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  `${process.env.BACKEND_URL}/api/auth/google/callback`
);

// ----------------- FUNÇÃO DE RESPOSTA DA IA -----------------
async function getAIResponse(chatHistory, userId) {
  try {
    const personaResult = await pool.query("SELECT ai_persona FROM users WHERE id = $1", [userId]);
    if (personaResult.rows.length === 0) return "Persona não configurada.";
    const persona = personaResult.rows[0].ai_persona;

    const historyForModel = chatHistory.map(msg => ({
      role: msg.role,
      parts: [{ text: msg.content }]
    }));

    const chat = model.startChat({
      history: [
        { role: 'user', parts: [{ text: `Assuma a seguinte persona e nunca saia dela: ${persona}` }] },
        { role: 'model', parts: [{ text: "Entendido. Estou pronto." }] },
        ...historyForModel.slice(0, -1)
      ],
    });

    const lastUserMessage = historyForModel[historyForModel.length - 1].parts[0].text;
    const result = await chat.sendMessage(lastUserMessage);
    const response = result.response;

    if (response?.candidates?.[0]?.content?.parts?.[0]?.text) {
      return response.candidates[0].content.parts[0].text;
    } else {
      console.error("ERRO DA IA: Resposta inválida ou sem conteúdo.", JSON.stringify(response, null, 2));
      return "Desculpe, a IA não conseguiu gerar uma resposta no momento.";
    }
  } catch (error) {
    console.error("ERRO DA IA:", error);
    return "Desculpe, ocorreu um erro na IA.";
  }
}

// ----------------- AUTENTICAÇÃO JWT -----------------
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// ----------------- ROTAS DE AUTENTICAÇÃO -----------------
app.post('/api/auth/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ success: false, message: 'Email e senha são obrigatórios.' });

  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = await pool.query(
      "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, created_at",
      [email, passwordHash]
    );
    res.status(201).json({ success: true, user: newUser.rows[0] });
  } catch (error) {
    if (error.code === '23505')
      return res.status(409).json({ success: false, message: 'Este email já está em uso.' });
    res.status(500).json({ success: false, message: 'Erro interno do servidor.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ success: false, message: 'Email e senha são obrigatórios.' });

  try {
    const userResult = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (userResult.rows.length === 0)
      return res.status(401).json({ success: false, message: 'Email ou senha inválidos.' });

    const user = userResult.rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch)
      return res.status(401).json({ success: false, message: 'Email ou senha inválidos.' });

    const accessToken = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.status(200).json({ success: true, accessToken, user: { id: user.id, email: user.email } });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Erro interno do servidor.' });
  }
});

// ----------------- GOOGLE LOGIN -----------------
app.get('/api/auth/google', (req, res) => {
  const authorizeUrl = oAuth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: ['https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email'],
  });
  res.redirect(authorizeUrl);
});

app.get('/api/auth/google/callback', async (req, res) => {
  const { code } = req.query;
  try {
    const { tokens } = await oAuth2Client.getToken(code);
    oAuth2Client.setCredentials(tokens);
    const userInfo = await oAuth2Client.request({ url: 'https://www.googleapis.com/oauth2/v3/userinfo' });
    const email = userInfo.data.email;

    let userResult = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (userResult.rows.length === 0) {
      const placeholderHash = 'google_authenticated';
      userResult = await pool.query(
        "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, created_at",
        [email, placeholderHash]
      );
    }

    const user = userResult.rows[0];
    const accessToken = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.redirect(`${process.env.FRONTEND_URL}?token=${accessToken}`);
  } catch (error) {
    res.redirect(`${process.env.FRONTEND_URL}?error=auth_failed`);
  }
});

// ----------------- ROTAS DE PERSONA (exemplo) -----------------
app.get('/api/config/persona', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query("SELECT ai_persona FROM users WHERE id = $1", [req.user.id]);
    if (result.rows.length === 0)
      return res.status(404).json({ success: false, message: 'Persona não encontrada.' });

    res.json({ success: true, persona: result.rows[0].ai_persona });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Erro ao buscar persona.' });
  }
});

app.put('/api/config/persona', authenticateToken, async (req, res) => {
  const { persona } = req.body;
  try {
    await pool.query("UPDATE users SET ai_persona = $1 WHERE id = $2", [persona, req.user.id]);
    res.json({ success: true, message: 'Persona atualizada com sucesso!' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Erro ao salvar persona.' });
  }
});

// ----------------- START SERVER -----------------
app.listen(PORT, () => {
  console.log(`[SERVER] Rodando na porta ${PORT}`);
});
