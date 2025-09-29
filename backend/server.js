// server.js - Versão Definitiva
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const { Client, LegacySessionAuth, NoAuth } = require('whatsapp-web.js');
const qrcode = require('qrcode');
const { VertexAI } = require('@google-cloud/vertexai');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');

const app = express();
const PORT = process.env.PORT || 10000;

app.use(express.json());
app.use(cors({ origin: process.env.FRONTEND_URL, optionsSuccessStatus: 200 }));

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
        console.error('[ERRO DB FATAL] Não foi possível conectar ao banco de dados:', error);
    }
}

const sessions = new Map();

// --- INICIALIZAÇÃO DA IA ---
let vertex_ai;
let model;
try {
    const decodedJsonString = Buffer.from(process.env.GOOGLE_CREDENTIALS_BASE64, 'base64').toString('utf-8');
    const credentials = JSON.parse(decodedJsonString);

    vertex_ai = new VertexAI({
        project: process.env.GOOGLE_PROJECT_ID,
        location: 'us-central1',
        credentials
    });

    model = vertex_ai.getGenerativeModel({ model: 'gemini-1.5-flash-latest' });
    console.log('[IA] Cliente Vertex AI inicializado com sucesso!');
} catch (error) {
    console.error('[ERRO IA FATAL] Falha na inicialização do cliente Vertex AI. Verifique as variáveis de ambiente GOOGLE_PROJECT_ID e GOOGLE_CREDENTIALS_BASE64.', error);
}

const oAuth2Client = new OAuth2Client(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    `${process.env.BACKEND_URL}/api/auth/google/callback`
);

async function getAIResponse(chatHistory, userId) {
    if (!model) {
        console.error("ERRO DA IA: Tentativa de uso com modelo não inicializado.");
        return "Desculpe, a IA não está disponível no momento devido a um erro de configuração.";
    }
    try {
        const personaResult = await pool.query("SELECT ai_persona FROM users WHERE id = $1", [userId]);
        const persona = personaResult.rows.length > 0 ? personaResult.rows[0].ai_persona : "Você é um assistente prestativo.";

        const historyForModel = chatHistory.map(msg => ({
            role: msg.role, parts: [{ text: msg.content }]
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
        console.error("ERRO DA IA (durante chamada):", error);
        return "Desculpe, ocorreu um erro na comunicação com a IA.";
    }
}

// ... (O RESTANTE DO SEU CÓDIGO DE ROTAS CONTINUA IGUAL)
// Cole este bloco de inicialização da IA e a função getAIResponse, mantendo o resto do seu server.js.
// Se preferir, me peça o arquivo completo novamente.

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) { return res.sendStatus(403); }
        req.user = user;
        next();
    });
}

app.get('/api/health', (req, res) => res.json({ status: 'ok', message: 'Sincro.space API está no ar!' }));
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
            const placeholderHash = `google_auth_${Date.now()}`;
            userResult = await pool.query("INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email", [email, placeholderHash]);
        }
        
        const user = userResult.rows[0];
        const accessToken = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.redirect(`${process.env.FRONTEND_URL}?token=${accessToken}`);
    } catch (error) {
        console.error("Erro no callback do Google:", error);
        res.redirect(`${process.env.FRONTEND_URL}?error=auth_failed`);
    }
});

app.use(authenticateToken); // Aplicar autenticação para as rotas abaixo

app.get('/api/config/persona', async (req, res) => {
    const result = await pool.query("SELECT ai_persona FROM users WHERE id = $1", [req.user.id]);
    res.json({ success: true, persona: result.rows[0]?.ai_persona || '' });
});

app.put('/api/config/persona', async (req, res) => {
    const { persona } = req.body;
    await pool.query("UPDATE users SET ai_persona = $1 WHERE id = $2", [persona, req.user.id]);
    res.json({ success: true, message: 'Persona atualizada!' });
});

// Adicione aqui as outras rotas (blocklist, contacts, sessions) que já estavam funcionando

app.post('/api/sessions/start', async (req, res) => {
    const clientId = req.user.id;
    if (sessions.has(clientId)) { return res.status(400).json({ success: false, message: 'Sessão já ativa ou iniciando.' }); }
    try {
        const { rows } = await pool.query('SELECT session_data FROM whatsapp_sessions WHERE user_id = $1', [clientId]);
        const client = new Client({
            authStrategy: rows.length > 0 ? new LegacySessionAuth({ session: rows[0].session_data }) : new NoAuth(),
            puppeteer: { headless: true, args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu'] }
        });
        sessions.set(clientId, { client, chatHistories: new Map() });

        client.on('qr', async (qr) => {
            const qrCodeDataUrl = await qrcode.toDataURL(qr);
            if (!res.headersSent) res.json({ success: true, qrCodeDataUrl });
        });
        client.on('authenticated', (session) => {
            if (session) pool.query(`INSERT INTO whatsapp_sessions (user_id, session_data) VALUES ($1, $2) ON CONFLICT (user_id) DO UPDATE SET session_data = $2`, [clientId, session]);
        });
        client.on('ready', () => {
            console.log(`[Usuário ID: ${clientId}] Cliente conectado e pronto!`);
            if (!res.headersSent) res.json({ success: true, message: 'Conectado com sessão salva!' });
        });
        client.on('disconnected', (reason) => {
            if (reason === 'LOGGED_OUT') pool.query('DELETE FROM whatsapp_sessions WHERE user_id = $1', [clientId]);
            sessions.delete(clientId);
            client.destroy().catch(() => {});
        });
        client.on('message', async (message) => {
            const chat = await message.getChat();
            if (chat.isGroup) return;

            const sessionData = sessions.get(clientId);
            if (!sessionData) return;
            
            const contactId = message.from;
            if (!sessionData.chatHistories.has(contactId)) sessionData.chatHistories.set(contactId, []);
            
            const chatHistory = sessionData.chatHistories.get(contactId);
            chatHistory.push({ role: 'user', content: message.body });
            if (chatHistory.length > 20) chatHistory.splice(0, chatHistory.length - 20);

            const aiResponse = await getAIResponse(chatHistory, clientId);
            chatHistory.push({ role: 'model', content: aiResponse });
            await client.sendMessage(message.from, aiResponse);
        });

        await client.initialize();
    } catch (error) {
        console.error(`[ID: ${clientId}] Erro ao iniciar sessão:`, error);
        sessions.delete(clientId);
        if (!res.headersSent) res.status(500).json({ success: false, message: 'Erro interno ao iniciar cliente.' });
    }
});
app.get('/api/sessions/status', async (req, res) => {
    const clientId = req.user.id;
    if (sessions.has(clientId)) {
        try {
            const status = await sessions.get(clientId).client.getState();
            return res.json({ success: true, status: status || 'INITIALIZING' });
        } catch {
            sessions.delete(clientId);
            return res.json({ success: true, status: 'ERROR_STATE' });
        }
    }
    const { rows } = await pool.query('SELECT 1 FROM whatsapp_sessions WHERE user_id = $1', [clientId]);
    return res.json({ success: true, status: rows.length > 0 ? 'SAVED_BUT_DISCONNECTED' : 'NOT_INITIALIZED' });
});

app.listen(PORT, () => {
    console.log(`Servidor do Sincro.space rodando na porta ${PORT}`);
    testDBConnection();
});