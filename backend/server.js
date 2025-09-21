// server.js - Versão 4.0: Memória de Curto Prazo e Preparação para Novas Features

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
// Configuração de CORS mais específica
const corsOptions = {
  origin: process.env.FRONTEND_URL, // Puxa a URL do seu .env
  optionsSuccessStatus: 200 
};

app.use(cors(corsOptions));

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

// NOVO: Estrutura de sessões aprimorada para guardar históricos de chat
const sessions = new Map();

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

// NOVO: Função de IA aprimorada para usar o histórico da conversa
async function getAIResponse(chatHistory, userId) {
    try {
        const personaResult = await pool.query("SELECT ai_persona FROM users WHERE id = $1", [userId]);
        if (personaResult.rows.length === 0) {
            return "Desculpe, não encontrei uma persona configurada para você.";
        }
        const persona = personaResult.rows[0].ai_persona;

        // Formata o histórico para a IA entender
        const formattedHistory = chatHistory.map(msg => `${msg.role}: ${msg.content}`).join('\n');
        
        const prompt = `${persona}\n\nA seguir está o histórico da conversa. Responda à última mensagem do "user" de forma natural e contextual.\n\n${formattedHistory}`;
        
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
// --- SESSIONS ENDPOINTS (Com Grandes Melhorias) ---
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
    
    // NOVO: Estrutura para guardar cliente e históricos
    sessions.set(clientId, {
        client: client,
        chatHistories: new Map() // Um mapa para cada contato (ex: '5541...': [histórico])
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

        // --- PONTOS DE MELHORIA FUTURA ---
        // TODO: Lógica de BLOQUEIO DE CONTATO virá aqui.
        // TODO: Lógica de salvar/atualizar CONTATO no "mini-CRM" virá aqui.

        const sessionData = sessions.get(clientId);
        if (!sessionData) return;

        const contactId = message.from;

        // NOVO: Gerenciamento do histórico da conversa
        if (!sessionData.chatHistories.has(contactId)) {
            sessionData.chatHistories.set(contactId, []);
        }
        const chatHistory = sessionData.chatHistories.get(contactId);

        // Adiciona a mensagem do usuário ao histórico
        chatHistory.push({ role: 'user', content: message.body });

        // Limita o histórico para não sobrecarregar a IA
        if (chatHistory.length > 20) { // 10 do user + 10 da IA
            chatHistory.splice(0, chatHistory.length - 20);
        }

        console.log(`>>> Pensando com a persona e histórico do contato ${contactId}...`);
        const aiResponse = await getAIResponse(chatHistory, clientId); // Envia o histórico completo

        // Adiciona a resposta da IA ao histórico
        chatHistory.push({ role: 'model', content: aiResponse });

        console.log(`<<< Resposta da IA: "${aiResponse}"`);
        await client.sendMessage(message.from, aiResponse);
    });

    client.on('disconnected', (reason) => {
        console.log(`[Usuário ID: ${clientId}] Cliente foi desconectado. Razão:`, reason);
        sessions.delete(clientId);
        client.destroy();
    });

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
    const client = sessions.get(clientId).client; // Pega o client de dentro da sessionData
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
    const client = sessions.get(clientId).client; // Pega o client de dentro da sessionData
    try {
        await client.logout();
        // O evento 'disconnected' vai lidar com a limpeza da sessão
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