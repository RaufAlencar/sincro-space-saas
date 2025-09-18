// server.js - Versão 3.6 (100% COMPLETO): Envia mensagem em vez de responder

// PARTE 0: Configuração de Ambiente
require('dotenv').config();

// PARTE 1: Importações e Configuração Inicial
const express = require('express');
const cors = require('cors');
const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcode = require('qrcode');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cors());

// Configuração da Conexão com o Banco de Dados
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
ssl: {
        rejectUnauthorized: false
    }
});

async function testDBConnection() {
    try {
        await pool.query('SELECT NOW()');
        console.log('[DB] Conexão com o banco de dados PostgreSQL bem-sucedida!');
    } catch (error) {
        console.error('[ERRO DB] Não foi possível conectar ao banco de dados:', error);
    }
}

const sessions = new Map();

// Chaves de API lidas do arquivo .env
const GEMINI_API_KEY = process.env.GEMINI_API_KEY; 

// Configuração do modelo de IA
const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-1.5-pro-latest" });

// Configuração do Cliente OAuth do Google (com URL de produção)
const oAuth2Client = new OAuth2Client(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    `${process.env.BACKEND_URL}/api/auth/google/callback`
);

// Função de IA MODIFICADA para usar a persona do banco de dados
async function getAIResponse(messageText, userId) {
    try {
        const personaResult = await pool.query("SELECT ai_persona FROM users WHERE id = $1", [userId]);
        if (personaResult.rows.length === 0) {
            return "Desculpe, não encontrei uma persona configurada para você.";
        }
        const persona = personaResult.rows[0].ai_persona;
        const prompt = `${persona}\n\nResponda a seguinte mensagem:\n"${messageText}"`;
        const result = await model.generateContent(prompt);
        const response = await result.response;
        const text = response.text();
        return text;
    } catch (error) {
        console.error("ERRO DA IA:", error);
        return "Desculpe, não consegui processar sua mensagem no momento.";
    }
}

// =================================================================
// --- MIDDLEWARE DE AUTENTICAÇÃO (O "SEGURANÇA") ---
// =================================================================

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.error('[ERRO JWT] Token inválido:', err.message);
            return res.sendStatus(403);
        }
        req.user = user;
        next();
    });
}

// =================================================================
// --- AUTH ENDPOINTS ---
// =================================================================

app.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email e senha são obrigatórios.' });
    }
    try {
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);
        const newUser = await pool.query(
            "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, created_at",
            [email, passwordHash]
        );
        res.status(201).json({ 
            success: true, 
            message: 'Usuário cadastrado com sucesso!', 
            user: newUser.rows[0] 
        });
    } catch (error) {
        console.error('[ERRO CADASTRO]', error);
        if (error.code === '23505') {
            return res.status(409).json({ success: false, message: 'Este email já está em uso.' });
        }
        res.status(500).json({ success: false, message: 'Erro interno do servidor.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email e senha são obrigatórios.' });
    }
    try {
        const userResult = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
        if (userResult.rows.length === 0) {
            return res.status(401).json({ success: false, message: 'Email ou senha inválidos.' });
        }
        const user = userResult.rows[0];
        const passwordMatch = await bcrypt.compare(password, user.password_hash);
        if (!passwordMatch) {
            return res.status(401).json({ success: false, message: 'Email ou senha inválidos.' });
        }
        const accessToken = jwt.sign(
            { id: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );
        res.status(200).json({
            success: true,
            message: 'Login bem-sucedido!',
            accessToken: accessToken,
            user: { id: user.id, email: user.email }
        });
    } catch (error) {
        console.error('[ERRO LOGIN]', error);
        res.status(500).json({ success: false, message: 'Erro interno do servidor.' });
    }
});

app.get('/api/auth/google', (req, res) => {
    const authorizeUrl = oAuth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: [
            'https://www.googleapis.com/auth/userinfo.profile',
            'https://www.googleapis.com/auth/userinfo.email',
        ],
    });
    res.redirect(authorizeUrl);
});

app.get('/api/auth/google/callback', async (req, res) => {
    const { code } = req.query;
    try {
        const { tokens } = await oAuth2Client.getToken(code);
        oAuth2Client.setCredentials(tokens);
        const userInfo = await oAuth2Client.request({
            url: 'https://www.googleapis.com/oauth2/v3/userinfo',
        });
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
        const accessToken = jwt.sign(
            { id: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );
        res.redirect(`${process.env.FRONTEND_URL}?token=${accessToken}`);
    } catch (error) {
        console.error('[ERRO GOOGLE AUTH]', error);
        res.redirect(`${process.env.FRONTEND_URL}?error=auth_failed`);
    }
});

// =================================================================
// --- CONFIG ENDPOINTS ---
// =================================================================

app.get('/api/config/persona', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const result = await pool.query("SELECT ai_persona FROM users WHERE id = $1", [userId]);
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: "Usuário não encontrado." });
        }
        res.json({ success: true, persona: result.rows[0].ai_persona });
    } catch (error) {
        console.error('[ERRO GET PERSONA]', error);
        res.status(500).json({ success: false, message: 'Erro ao buscar persona.' });
    }
});

app.put('/api/config/persona', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const { persona } = req.body;
        if (typeof persona !== 'string') {
            return res.status(400).json({ success: false, message: "O campo 'persona' é obrigatório e deve ser um texto." });
        }
        await pool.query("UPDATE users SET ai_persona = $1 WHERE id = $2", [persona, userId]);
        res.json({ success: true, message: 'Persona atualizada com sucesso!' });
    } catch (error) {
        console.error('[ERRO UPDATE PERSONA]', error);
        res.status(500).json({ success: false, message: 'Erro ao atualizar persona.' });
    }
});

// =================================================================
// --- SESSIONS ENDPOINTS (Protegidos) ---
// =================================================================

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'Sincro.space API está no ar!' });
});

app.post('/api/sessions/start', authenticateToken, async (req, res) => {
    const clientId = req.user.id;
    if (sessions.has(clientId)) {
        return res.status(400).json({ success: false, message: 'Sessão já iniciada para este cliente.' });
    }
    console.log(`[Usuário ID: ${clientId}] Iniciando criação de sessão...`);
    const client = new Client({
        authStrategy: new LocalAuth({ clientId: `session-${clientId}` }),
        puppeteer: { headless: true, args: ['--no-sandbox'] }
    });
    let qrSent = false;
    client.on('qr', async (qr) => {
        if (qrSent) return;
        qrSent = true;
        console.log(`[Usuário ID: ${clientId}] QR Code recebido! Gerando imagem...`);
        try {
            const qrCodeDataUrl = await qrcode.toDataURL(qr);
            if (!res.headersSent) {
                res.json({ success: true, message: 'QR Code gerado. Leia com seu celular.', qrCodeDataUrl });
            }
        } catch (err) {
            console.error(`[Usuário ID: ${clientId}] Erro ao gerar QR Code Data URL:`, err);
            if (!res.headersSent) {
                res.status(500).json({ success: false, message: 'Erro ao gerar QR Code.' });
            }
        }
    });
    client.on('ready', () => {
        console.log(`[Usuário ID: ${clientId}] Cliente está pronto e conectado!`);
        if (!res.headersSent && !qrSent) {
             res.json({ success: true, message: 'Cliente conectado com sessão salva!'});
        }
    });
    client.on('message', async (message) => {
        const chat = await message.getChat();
        if (message.from === 'status@broadcast' || chat.isGroup) {
            return;
        }
        console.log('-----------------------------------------');
        console.log(`[Usuário ID: ${clientId}] Mensagem recebida!`);
        console.log(`De: ${message.from}`);
        console.log(`Mensagem: "${message.body}"`);
        console.log('>>> Pensando com a persona do banco...');
        const aiResponse = await getAIResponse(message.body, clientId);
        console.log(`<<< Resposta da IA: "${aiResponse}"`);

        // >>>>> LINHA ALTERADA AQUI <<<<<
        await client.sendMessage(message.from, aiResponse); // Usa client.sendMessage em vez de message.reply

        console.log('>>> Resposta enviada com sucesso!');
        console.log('-----------------------------------------');
    });
    client.on('disconnected', (reason) => {
        console.log(`[Usuário ID: ${clientId}] Cliente foi desconectado. Razão:`, reason);
        sessions.delete(clientId);
        client.destroy();
    });
    sessions.set(clientId, client);
    try {
        await client.initialize();
    } catch (error) {
        console.error(`[Usuário ID: ${clientId}] Erro ao inicializar o cliente:`, error);
        sessions.delete(clientId);
        if (!res.headersSent) {
            res.status(500).json({ success: false, message: 'Falha ao inicializar a sessão do WhatsApp.' });
        }
    }
});

app.get('/api/sessions/status', authenticateToken, async (req, res) => {
    const clientId = req.user.id;
    if (!sessions.has(clientId)) {
        return res.json({ success: true, status: 'disconnected', message: 'Nenhuma sessão encontrada para este cliente.' });
    }
    const client = sessions.get(clientId);
    try {
        const status = await client.getState();
        res.json({ success: true, status: status, message: 'Status da sessão recuperado.' });
    } catch (error) {
        res.json({ success: true, status: 'unknown_error', message: 'Erro ao verificar o status da sessão.' });
    }
});

app.post('/api/sessions/stop', authenticateToken, async (req, res) => {
    const clientId = req.user.id;
    if (!sessions.has(clientId)) {
        return res.json({ success: true, message: 'Nenhuma sessão ativa para finalizar.' });
    }
    console.log(`[Usuário ID: ${clientId}] Finalizando sessão...`);
    const client = sessions.get(clientId);
    try {
        await client.logout();
        res.json({ success: true, message: 'Sessão finalizada com sucesso.' });
    } catch (error) {
        sessions.delete(clientId); 
        res.status(500).json({ success: false, message: 'Erro ao finalizar a sessão.' });
    }
});

// PARTE FINAL: Inicia o servidor
app.listen(PORT, () => {
    console.log(`Servidor do Sincro.space rodando na porta ${PORT}`);
    testDBConnection();
});