require('dotenv').config();

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

const corsOptions = {
  origin: process.env.FRONTEND_URL,
  optionsSuccessStatus: 200 
};
app.use(cors(corsOptions));

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
const GEMINI_API_KEY = process.env.GEMINI_API_KEY; 
const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-1.5-pro-latest" });

const oAuth2Client = new OAuth2Client(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    `${process.env.BACKEND_URL}/api/auth/google/callback`
);

async function getAIResponse(chatHistory, userId) {
    try {
        const personaResult = await pool.query("SELECT ai_persona FROM users WHERE id = $1", [userId]);
        if (personaResult.rows.length === 0) {
            return "Persona não configurada.";
        }
        const persona = personaResult.rows[0].ai_persona;
        const formattedHistory = chatHistory.map(msg => `${msg.role}: ${msg.content}`).join('\n');
        const prompt = `${persona}\n\nHistórico da conversa:\n${formattedHistory}\n\nResponda à última mensagem do "user":`;
        const result = await model.generateContent(prompt);
        const response = await result.response;
        return response.text();
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
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

app.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'Email e senha são obrigatórios.' });
    try {
        const passwordHash = await bcrypt.hash(password, 10);
        const newUser = await pool.query(
            "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email",
            [email, passwordHash]
        );
        res.status(201).json({ success: true, user: newUser.rows[0] });
    } catch (error) {
        if (error.code === '23505') return res.status(409).json({ success: false, message: 'Este email já está em uso.' });
        res.status(500).json({ success: false, message: 'Erro interno do servidor.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'Email e senha são obrigatórios.' });
    try {
        const userResult = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
        if (userResult.rows.length === 0) return res.status(401).json({ success: false, message: 'Email ou senha inválidos.' });
        
        const user = userResult.rows[0];
        const passwordMatch = await bcrypt.compare(password, user.password_hash);
        if (!passwordMatch) return res.status(401).json({ success: false, message: 'Email ou senha inválidos.' });

        const accessToken = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.status(200).json({ success: true, accessToken, user: { id: user.id, email: user.email }});
    } catch (error) {
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
            userResult = await pool.query(
                "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING *",
                [email, 'google_authenticated']
            );
        }
        const user = userResult.rows[0];
        const accessToken = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.redirect(`${process.env.FRONTEND_URL}?token=${accessToken}`);
    } catch (error) {
        res.redirect(`${process.env.FRONTEND_URL}?error=auth_failed`);
    }
});

app.get('/api/config/persona', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query("SELECT ai_persona FROM users WHERE id = $1", [req.user.id]);
        if (result.rows.length === 0) return res.status(404).json({ success: false, message: "Usuário não encontrado." });
        res.json({ success: true, persona: result.rows[0].ai_persona });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erro ao buscar persona.' });
    }
});

app.put('/api/config/persona', authenticateToken, async (req, res) => {
    const { persona } = req.body;
    if (typeof persona !== 'string') return res.status(400).json({ success: false, message: "O campo 'persona' é obrigatório." });
    try {
        await pool.query("UPDATE users SET ai_persona = $1 WHERE id = $2", [persona, req.user.id]);
        res.json({ success: true, message: 'Persona atualizada com sucesso!' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erro ao atualizar persona.' });
    }
});

app.get('/api/blocklist', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query("SELECT phone_number FROM blocked_contacts WHERE user_id = $1", [req.user.id]);
        res.json({ success: true, blocklist: result.rows.map(r => r.phone_number) });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erro ao buscar lista de bloqueio.' });
    }
});

app.post('/api/blocklist', authenticateToken, async (req, res) => {
    const { phoneNumber } = req.body;
    if (!phoneNumber) return res.status(400).json({ success: false, message: 'Número de telefone é obrigatório.' });
    try {
        await pool.query("INSERT INTO blocked_contacts (user_id, phone_number) VALUES ($1, $2)", [req.user.id, phoneNumber]);
        res.status(201).json({ success: true, message: 'Contato bloqueado com sucesso.' });
    } catch (error) {
        if (error.code === '23505') return res.status(409).json({ success: false, message: 'Este contato já está bloqueado.' });
        res.status(500).json({ success: false, message: 'Erro ao bloquear contato.' });
    }
});

app.delete('/api/blocklist/:phoneNumber', authenticateToken, async (req, res) => {
    const { phoneNumber } = req.params;
    try {
        await pool.query("DELETE FROM blocked_contacts WHERE user_id = $1 AND phone_number = $2", [req.user.id, phoneNumber]);
        res.json({ success: true, message: 'Contato desbloqueado.' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erro ao desbloquear contato.' });
    }
});

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

app.post('/api/sessions/start', authenticateToken, async (req, res) => {
    const clientId = req.user.id;
    if (sessions.has(clientId)) return res.status(400).json({ success: false, message: 'Sessão já iniciada.' });

    console.log(`[Usuário ID: ${clientId}] Iniciando sessão...`);
    const client = new Client({
        authStrategy: new LocalAuth({ clientId: `session-${clientId}` }),
        puppeteer: { headless: true, args: ['--no-sandbox'] }
    });
    
    sessions.set(clientId, { client, chatHistories: new Map() });

    client.on('qr', async (qr) => {
        try {
            const qrCodeDataUrl = await qrcode.toDataURL(qr);
            if (!res.headersSent) res.json({ success: true, qrCodeDataUrl });
        } catch (err) {
            if (!res.headersSent) res.status(500).json({ success: false, message: 'Erro ao gerar QR Code.' });
        }
    });
    
    client.on('ready', () => {
        console.log(`[Usuário ID: ${clientId}] Cliente conectado!`);
        if (!res.headersSent) res.json({ success: true, message: 'Conectado com sessão salva!'});
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
            if (isBlockedRes.rows.length > 0) {
                console.log(`[Usuário ID: ${clientId}] Mensagem ignorada do contato bloqueado: ${contactNumber}`);
                return;
            }

            const contactExists = await pool.query("SELECT 1 FROM contacts WHERE user_id = $1 AND phone_number = $2", [clientId, contactNumber]);
            if (contactExists.rows.length === 0) {
                const contactInfo = await message.getContact();
                const name = contactInfo.pushname || contactInfo.name || contactNumber;
                await pool.query("INSERT INTO contacts (user_id, phone_number, name) VALUES ($1, $2, $3)", [clientId, contactNumber, name]);
                console.log(`[Usuário ID: ${clientId}] Novo contato salvo: ${name} (${contactNumber})`);
            }

            if (!sessionData.chatHistories.has(contactId)) {
                sessionData.chatHistories.set(contactId, []);
            }
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

    client.on('disconnected', (reason) => {
        console.log(`[Usuário ID: ${clientId}] Cliente desconectado:`, reason);
        sessions.delete(clientId);
        client.destroy();
    });

    try {
        await client.initialize();
    } catch (error) {
        console.error(`[ERRO] Usuário ID ${clientId}:`, error);
        sessions.delete(clientId);
        if (!res.headersSent) res.status(500).json({ success: false, message: 'Falha ao inicializar sessão.' });
    }
});

app.get('/api/sessions/status', authenticateToken, async (req, res) => {
    const clientId = req.user.id;
    if (!sessions.has(clientId)) return res.json({ success: true, status: 'disconnected' });
    
    const client = sessions.get(clientId).client;
    try {
        const status = await client.getState();
        res.json({ success: true, status });
    } catch (error) {
        res.json({ success: true, status: 'unknown_error' });
    }
});

app.post('/api/sessions/stop', authenticateToken, async (req, res) => {
    const clientId = req.user.id;
    if (!sessions.has(clientId)) return res.json({ success: true, message: 'Nenhuma sessão ativa.' });

    const client = sessions.get(clientId).client;
    try {
        await client.logout();
        res.json({ success: true, message: 'Sessão finalizada.' });
    } catch (error) {
        sessions.delete(clientId); 
        res.status(500).json({ success: false, message: 'Erro ao finalizar sessão.' });
    }
});

app.listen(PORT, () => {
    console.log(`Servidor do Sincro.space rodando na porta ${PORT}`);
    testDBConnection();
});