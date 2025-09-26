// server.js - Versão 8.2 (Modelo Flash)
// - Altera o modelo para 'gemini-1.5-flash-latest', um modelo rápido e com alta disponibilidade.

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
const PORT = process.env.PORT || 3000;

app.use(express.json());

const corsOptions = {
  origin: process.env.FRONTEND_URL,
  optionsSuccessStatus: 200 
};
app.use(cors(corsOptions));

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    },
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

const sessions = new Map();

// Inicialização da IA com Vertex AI
const vertex_ai = new VertexAI({
    project: process.env.GCP_PROJECT_ID, 
    location: process.env.GCP_LOCATION 
});

const model = vertex_ai.getGenerativeModel({
    model: 'gemini-1.5-flash-latest', // <-- MUDANÇA FINAL AQUI
});

const oAuth2Client = new OAuth2Client(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    `${process.env.BACKEND_URL}/api/auth/google/callback`
);

async function getAIResponse(chatHistory, userId) {
    try {
        const personaResult = await pool.query("SELECT ai_persona FROM users WHERE id = $1", [userId]);
        if (personaResult.rows.length === 0) { return "Persona não configurada."; }
        const persona = personaResult.rows[0].ai_persona;
        
        const history = chatHistory.map(msg => ({
            role: msg.role === 'model' ? 'model' : 'user',
            parts: [{ text: msg.content }]
        }));

        const chat = model.startChat({
            history: [
                { role: 'user', parts: [{ text: persona }] },
                { role: 'model', parts: [{ text: "Entendido. Estou pronto para assumir a persona e responder como tal." }] },
                ...history.slice(0, -1)
            ]
        });

        const lastUserMessage = history[history.length - 1].parts[0].text;
        const result = await chat.sendMessage(lastUserMessage);
        const response = result.response;
        return response.candidates[0].content.parts[0].text;
    } catch (error) {
        console.error("ERRO DA IA:", error);
        return "Desculpe, ocorreu um erro na IA.";
    }
}

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

app.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) { return res.status(400).json({ success: false, message: 'Email e senha são obrigatórios.' }); }
    try {
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);
        const newUser = await pool.query("INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, created_at", [email, passwordHash]);
        res.status(201).json({ success: true, message: 'Usuário cadastrado com sucesso!', user: newUser.rows[0] });
    } catch (error) {
        console.error('[ERRO CADASTRO]', error);
        if (error.code === '23505') { return res.status(409).json({ success: false, message: 'Este email já está em uso.' }); }
        res.status(500).json({ success: false, message: 'Erro interno do servidor.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) { return res.status(400).json({ success: false, message: 'Email e senha são obrigatórios.' }); }
    try {
        const userResult = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
        if (userResult.rows.length === 0) { return res.status(401).json({ success: false, message: 'Email ou senha inválidos.' }); }
        const user = userResult.rows[0];
        const passwordMatch = await bcrypt.compare(password, user.password_hash);
        if (!passwordMatch) { return res.status(401).json({ success: false, message: 'Email ou senha inválidos.' }); }
        const accessToken = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.status(200).json({ success: true, message: 'Login bem-sucedido!', accessToken: accessToken, user: { id: user.id, email: user.email } });
    } catch (error) {
        console.error('[ERRO LOGIN]', error);
        res.status(500).json({ success: false, message: 'Erro interno do servidor.' });
    }
});

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
            userResult = await pool.query("INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, created_at", [email, placeholderHash]);
        }
        const user = userResult.rows[0];
        const accessToken = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.redirect(`${process.env.FRONTEND_URL}?token=${accessToken}`);
    } catch (error) {
        console.error('[ERRO GOOGLE AUTH]', error);
        res.redirect(`${process.env.FRONTEND_URL}?error=auth_failed`);
    }
});

app.get('/api/config/persona', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query("SELECT ai_persona FROM users WHERE id = $1", [req.user.id]);
        if (result.rows.length === 0) { return res.status(404).json({ success: false, message: "Usuário não encontrado." }); }
        res.json({ success: true, persona: result.rows[0].ai_persona });
    } catch (error) {
        console.error('[ERRO GET PERSONA]', error);
        res.status(500).json({ success: false, message: 'Erro ao buscar persona.' });
    }
});

app.put('/api/config/persona', authenticateToken, async (req, res) => {
    const { persona } = req.body;
    if (typeof persona !== 'string') { return res.status(400).json({ success: false, message: "O campo 'persona' é obrigatório." }); }
    try {
        await pool.query("UPDATE users SET ai_persona = $1 WHERE id = $2", [persona, req.user.id]);
        res.json({ success: true, message: 'Persona atualizada com sucesso!' });
    } catch (error) {
        console.error('[ERRO UPDATE PERSONA]', error);
        res.status(500).json({ success: false, message: 'Erro ao atualizar persona.' });
    }
});

app.get('/api/blocklist', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query("SELECT phone_number FROM blocked_contacts WHERE user_id = $1", [req.user.id]);
        res.json({ success: true, blocklist: result.rows.map(r => r.phone_number) });
    } catch (error) {
        console.error('[ERRO GET BLOCKLIST]', error);
        res.status(500).json({ success: false, message: 'Erro ao buscar lista de bloqueio.' });
    }
});

app.post('/api/blocklist', authenticateToken, async (req, res) => {
    const { phoneNumber } = req.body;
    if (!phoneNumber) { return res.status(400).json({ success: false, message: 'Número de telefone é obrigatório.' }); }
    try {
        await pool.query("INSERT INTO blocked_contacts (user_id, phone_number) VALUES ($1, $2)", [req.user.id, phoneNumber]);
        res.status(201).json({ success: true, message: 'Contato bloqueado com sucesso.' });
    } catch (error) {
        console.error('[ERRO POST BLOCKLIST]', error);
        if (error.code === '23505') { return res.status(409).json({ success: false, message: 'Este contato já está bloqueado.' }); }
        res.status(500).json({ success: false, message: 'Erro ao bloquear contato.' });
    }
});

app.delete('/api/blocklist/:phoneNumber', authenticateToken, async (req, res) => {
    const { phoneNumber } = req.params;
    try {
        await pool.query("DELETE FROM blocked_contacts WHERE user_id = $1 AND phone_number = $2", [req.user.id, phoneNumber]);
        res.json({ success: true, message: 'Contato desbloqueado.' });
    } catch (error) {
        console.error('[ERRO DELETE BLOCKLIST]', error);
        res.status(500).json({ success: false, message: 'Erro ao desbloquear contato.' });
    }
});

app.get('/api/contacts', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query("SELECT id, phone_number, name, tags FROM contacts WHERE user_id = $1 ORDER BY name", [req.user.id]);
        res.json({ success: true, contacts: result.rows });
    } catch (error) {
        console.error('[ERRO GET CONTACTS]', error);
        res.status(500).json({ success: false, message: 'Erro ao buscar contatos.' });
    }
});

app.put('/api/contacts/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { tags } = req.body;
    if (!Array.isArray(tags)) { return res.status(400).json({ success: false, message: "Tags devem ser um array." }); }
    try {
        await pool.query("UPDATE contacts SET tags = $1 WHERE id = $2 AND user_id = $3", [tags, id, req.user.id]);
        res.json({ success: true, message: 'Tags atualizadas com sucesso!' });
    } catch (error) {
        console.error('[ERRO UPDATE CONTACTS]', error);
        res.status(500).json({ success: false, message: 'Erro ao atualizar tags.' });
    }
});

app.get('/api/health', (req, res) => res.json({ status: 'ok', message: 'Sincro.space API está no ar!' }));

app.post('/api/sessions/start', authenticateToken, async (req, res) => {
    const clientId = req.user.id;
    if (sessions.has(clientId)) { return res.status(400).json({ success: false, message: 'Sessão já está em processo de inicialização ou ativa.' }); }
    console.log(`[Usuário ID: ${clientId}] Tentando iniciar sessão...`);
    try {
        const { rows } = await pool.query('SELECT session_data FROM whatsapp_sessions WHERE user_id = $1', [clientId]);
        const savedSession = rows.length > 0 ? rows[0].session_data : null;
        const client = new Client({
            authStrategy: savedSession ? new LegacySessionAuth({ session: savedSession }) : new NoAuth(),
            puppeteer: { headless: true, args: ['--no-sandbox', '--disable-gpu'] }
        });
        sessions.set(clientId, { client, chatHistories: new Map() });
        let qrSent = false;
        client.on('qr', async (qr) => {
            if (qrSent) return;
            qrSent = true;
            console.log(`[Usuário ID: ${clientId}] Gerando QR Code...`);
            const qrCodeDataUrl = await qrcode.toDataURL(qr);
            if (!res.headersSent) { res.json({ success: true, message: 'QR Code gerado.', qrCodeDataUrl }); }
        });
        client.on('authenticated', async (session) => {
            console.log(`[Usuário ID: ${clientId}] Autenticado! Salvando sessão no DB.`);
            if (session) { await pool.query(`INSERT INTO whatsapp_sessions (user_id, session_data) VALUES ($1, $2) ON CONFLICT (user_id) DO UPDATE SET session_data = $2, updated_at = NOW()`, [clientId, session]); }
        });
        client.on('ready', () => {
            console.log(`[Usuário ID: ${clientId}] Cliente conectado e pronto!`);
            if (!qrSent && !res.headersSent) { res.json({ success: true, message: 'Conectado com sessão salva!' }); }
        });
        client.on('auth_failure', async (msg) => {
            console.error(`[Usuário ID: ${clientId}] FALHA DE AUTENTICAÇÃO: ${msg}`);
            await pool.query('DELETE FROM whatsapp_sessions WHERE user_id = $1', [clientId]);
            sessions.delete(clientId);
            if (client) client.destroy();
        });
        client.on('disconnected', async (reason) => {
            console.log(`[Usuário ID: ${clientId}] Cliente desconectado:`, reason);
            if (reason === 'LOGGED_OUT') { await pool.query('DELETE FROM whatsapp_sessions WHERE user_id = $1', [clientId]); }
            sessions.delete(clientId);
            if (client) client.destroy().catch(err => console.error(`[ID: ${clientId}] Erro ao destruir cliente:`, err));
        });
        client.on('message', async (message) => {
            const chat = await message.getChat();
            if (message.from === 'status@broadcast' || chat.isGroup) return;
            const sessionData = sessions.get(clientId);
            if (!sessionData) return;
            const contactId = message.from;
            const contactNumber = contactId.split('@')[0];
            try {
                const isBlockedRes = await pool.query("SELECT 1 FROM blocked_contacts WHERE user_id = $1 AND phone_number = $2", [clientId, contactNumber]);
                if (isBlockedRes.rows.length > 0) { return; }
                const contactExists = await pool.query("SELECT 1 FROM contacts WHERE user_id = $1 AND phone_number = $2", [clientId, contactNumber]);
                if (contactExists.rows.length === 0) {
                    const contactInfo = await message.getContact();
                    const name = contactInfo.pushname || contactInfo.name || contactNumber;
                    await pool.query("INSERT INTO contacts (user_id, phone_number, name) VALUES ($1, $2, $3)", [clientId, contactNumber, name]);
                    console.log(`[Usuário ID: ${clientId}] Novo contato salvo: ${name} (${contactNumber})`);
                }
                if (!sessionData.chatHistories.has(contactId)) { sessionData.chatHistories.set(contactId, []); }
                const chatHistory = sessionData.chatHistories.get(contactId);
                chatHistory.push({ role: 'user', content: message.body });
                if (chatHistory.length > 20) chatHistory.splice(0, chatHistory.length - 20);
                const aiResponse = await getAIResponse(chatHistory, clientId);
                chatHistory.push({ role: 'model', content: aiResponse });
                await client.sendMessage(message.from, aiResponse);
            } catch (dbError) {
                console.error(`[ERRO DB on message] Usuário ID ${clientId}:`, dbError);
            }
        });
        await client.initialize();
    } catch (error) {
        console.error(`[ERRO CRÍTICO] Falha ao iniciar sessão para ${clientId}:`, error);
        sessions.delete(clientId);
        if (!res.headersSent) { res.status(500).json({ success: false, message: 'Erro interno ao inicializar o cliente.' }); }
    }
});

app.get('/api/sessions/status', authenticateToken, async (req, res) => {
    const clientId = req.user.id;
    if (sessions.has(clientId)) {
        const client = sessions.get(clientId).client;
        try {
            const status = await client.getState();
            return res.json({ success: true, status });
        } catch (error) {
            console.error(`[ERRO STATUS] Usuário ${clientId}:`, error.message);
            sessions.delete(clientId);
            return res.json({ success: true, status: 'ERROR_STATE' });
        }
    }
    try {
        const { rows } = await pool.query('SELECT 1 FROM whatsapp_sessions WHERE user_id = $1', [clientId]);
        if (rows.length > 0) { return res.json({ success: true, status: 'SAVED_BUT_DISCONNECTED' }); }
    } catch (dbError) {
        console.error('[ERRO DB STATUS]', dbError);
        return res.status(500).json({ success: false, message: 'Erro ao verificar status da sessão.' });
    }
    return res.json({ success: true, status: 'NOT_INITIALIZED' });
});

app.post('/api/sessions/stop', authenticateToken, async (req, res) => {
    const clientId = req.user.id;
    if (!sessions.has(clientId)) { return res.json({ success: true, message: 'Nenhuma sessão ativa para finalizar.' }); }
    const client = sessions.get(clientId).client;
    try {
        await client.logout(); 
        res.json({ success: true, message: 'Sessão finalizada com sucesso.' });
    } catch (error) {
        console.error(`[ERRO LOGOUT] Usuário ${clientId}:`, error);
        sessions.delete(clientId); 
        if (client) client.destroy().catch(err => console.error(`[ID: ${clientId}] Erro no stop forçado:`, err));
        res.status(500).json({ success: false, message: 'Erro ao finalizar sessão.' });
    }
});

app.listen(PORT, () => {
    console.log(`Servidor do Sincro.space rodando na porta ${PORT}`);
    testDBConnection();
});