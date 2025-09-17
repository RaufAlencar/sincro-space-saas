// script.js - Versão 3.2 (Pronto para Deploy)

// NOVO: Definimos a URL do nosso backend em um só lugar
const API_BASE_URL = 'https://app-sincro-space.onrender.com';

// Seleciona todos os elementos da página que vamos usar
const loginSection = document.getElementById('login-section');
const appSection = document.getElementById('app-section');
const connectBtn = document.getElementById('connect-btn');
const qrContainer = document.getElementById('qr-container');

// Novos elementos do painel
const statusDot = document.getElementById('status-dot');
const statusText = document.getElementById('status-text');
const personaTextarea = document.getElementById('persona-textarea');
const savePersonaBtn = document.getElementById('save-persona-btn');
const saveFeedback = document.getElementById('save-feedback');

// Função para buscar o status da conexão com o WhatsApp
async function fetchStatus() {
    const token = localStorage.getItem('accessToken');
    if (!token) return;

    try {
        // Usa a nova constante da API
        const response = await fetch(`${API_BASE_URL}/api/sessions/status`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await response.json();

        if (data.status === 'CONNECTED') {
            statusDot.classList.remove('offline');
            statusDot.classList.add('online');
            statusText.textContent = 'Conectado';
            connectBtn.classList.add('hidden');
        } else {
            statusDot.classList.remove('online');
            statusDot.classList.add('offline');
            statusText.textContent = 'Desconectado';
            connectBtn.classList.remove('hidden');
        }
    } catch (error) {
        console.error('Erro ao buscar status:', error);
    }
}

// Função para buscar a persona atual do usuário
async function fetchPersona() {
    const token = localStorage.getItem('accessToken');
    if (!token) return;

    try {
        // Usa a nova constante da API
        const response = await fetch(`${API_BASE_URL}/api/config/persona`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await response.json();
        if (data.success) {
            personaTextarea.value = data.persona;
        }
    } catch (error) {
        console.error('Erro ao buscar persona:', error);
    }
}

// Função para salvar a nova persona
savePersonaBtn.addEventListener('click', async () => {
    const token = localStorage.getItem('accessToken');
    const newPersona = personaTextarea.value;
    
    try {
        // Usa a nova constante da API
        const response = await fetch(`${API_BASE_URL}/api/config/persona`, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ persona: newPersona })
        });

        const data = await response.json();
        if (data.success) {
            saveFeedback.classList.remove('hidden');
            setTimeout(() => saveFeedback.classList.add('hidden'), 2000);
        } else {
            alert(data.message);
        }
    } catch (error) {
        console.error('Erro ao salvar persona:', error);
    }
});

// Função principal que roda assim que a página carrega
document.addEventListener('DOMContentLoaded', () => {
    const params = new URLSearchParams(window.location.search);
    const token = params.get('token');

    if (token) {
        localStorage.setItem('accessToken', token);
        window.history.pushState({}, document.title, "/"); 
        showAppSection();
    } else if (localStorage.getItem('accessToken')) {
        showAppSection();
    } else {
        showLoginSection();
    }
});

// Função para mostrar a tela principal do app (usuário logado)
function showAppSection() {
    loginSection.classList.add('hidden');
    appSection.classList.remove('hidden');
    fetchStatus();
    fetchPersona();
}

// Função para mostrar a tela de login (usuário deslogado)
function showLoginSection() {
    loginSection.classList.remove('hidden');
    appSection.classList.add('hidden');
}

// Lógica do botão de Conectar WhatsApp
connectBtn.addEventListener('click', async () => {
    console.log('Botão de conectar clicado!');
    connectBtn.textContent = 'Gerando QR Code...';
    connectBtn.disabled = true;

    const token = localStorage.getItem('accessToken');

    if (!token) {
        alert('Erro de autenticação. Por favor, faça login novamente.');
        showLoginSection();
        return;
    }
    
    try {
        // Usa a nova constante da API
        const response = await fetch(`${API_BASE_URL}/api/sessions/start`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (!response.ok) {
            throw new Error(`Falha na autenticação: ${response.statusText}`);
        }

        const data = await response.json();

        if (data.success) {
            console.log('QR Code recebido da API!');
            qrContainer.innerHTML = '';
            const img = document.createElement('img');
            img.src = data.qrCodeDataUrl;
            qrContainer.appendChild(img);
            connectBtn.style.display = 'none';
        } else {
            alert(data.message);
            connectBtn.textContent = 'Conectar WhatsApp';
            connectBtn.disabled = false;
        }

    } catch (error) {
        console.error('Erro ao conectar com a API:', error);
        alert('Não foi possível conectar ao servidor ou sua sessão expirou.');
        connectBtn.textContent = 'Conectar WhatsApp';
        connectBtn.disabled = false;
    }
});