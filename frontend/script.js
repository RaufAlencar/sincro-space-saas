const API_BASE_URL = 'https://app-sincro-space.onrender.com';

const loginSection = document.getElementById('login-section');
const appSection = document.getElementById('app-section');
const connectBtn = document.getElementById('connect-btn');
const qrContainer = document.getElementById('qr-container');
const statusDot = document.getElementById('status-dot');
const statusText = document.getElementById('status-text');
const personaTextarea = document.getElementById('persona-textarea');
const savePersonaBtn = document.getElementById('save-persona-btn');
const saveFeedback = document.getElementById('save-feedback');
const blockForm = document.getElementById('block-form');
const blockInput = document.getElementById('block-input');
const blockList = document.getElementById('block-list');

const getToken = () => localStorage.getItem('accessToken');

async function apiRequest(endpoint, method = 'GET', body = null) {
    const token = getToken();
    if (!token) {
        showLoginSection();
        throw new Error('Token não encontrado.');
    }

    const options = {
        method,
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        }
    };

    if (body) {
        options.body = JSON.stringify(body);
    }

    const response = await fetch(`${API_BASE_URL}${endpoint}`, options);

    if (response.status === 401 || response.status === 403) {
        localStorage.removeItem('accessToken');
        showLoginSection();
        throw new Error('Sessão expirada.');
    }

    return response.json();
}

async function fetchStatus() {
    try {
        const data = await apiRequest('/api/sessions/status');
        const isConnected = data.status === 'CONNECTED';
        statusDot.className = `status-dot ${isConnected ? 'online' : 'offline'}`;
        statusText.textContent = isConnected ? 'Conectado' : 'Desconectado';
        document.getElementById('connection-controls').classList.toggle('hidden', isConnected);
    } catch (error) {
        console.error('Erro ao buscar status:', error);
    }
}

async function fetchPersona() {
    try {
        const data = await apiRequest('/api/config/persona');
        if (data.success) {
            personaTextarea.value = data.persona;
        }
    } catch (error) {
        console.error('Erro ao buscar persona:', error);
    }
}

async function loadBlocklist() {
    try {
        const data = await apiRequest('/api/blocklist');
        blockList.innerHTML = '';
        if (data.success) {
            data.blocklist.forEach(renderBlockedContact);
        }
    } catch (error) {
        console.error('Erro ao carregar lista de bloqueio:', error);
    }
}

function renderBlockedContact(phoneNumber) {
    const li = document.createElement('li');
    li.dataset.number = phoneNumber;
    li.innerHTML = `
        <span>${phoneNumber}</span>
        <button class="unblock-btn">&times;</button>
    `;
    blockList.appendChild(li);
}

savePersonaBtn.addEventListener('click', async () => {
    try {
        const data = await apiRequest('/api/config/persona', 'PUT', { persona: personaTextarea.value });
        if (data.success) {
            saveFeedback.textContent = 'Salvo com sucesso!';
            saveFeedback.classList.remove('hidden');
            setTimeout(() => saveFeedback.classList.add('hidden'), 2000);
        }
    } catch (error) {
        console.error('Erro ao salvar persona:', error);
    }
});

blockForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const phoneNumber = blockInput.value.trim();
    if (!phoneNumber) return;

    try {
        const data = await apiRequest('/api/blocklist', 'POST', { phoneNumber });
        if (data.success) {
            renderBlockedContact(phoneNumber);
            blockInput.value = '';
        } else {
            alert(data.message);
        }
    } catch (error) {
        console.error('Erro ao bloquear contato:', error);
    }
});

blockList.addEventListener('click', async (e) => {
    if (e.target.classList.contains('unblock-btn')) {
        const listItem = e.target.closest('li');
        const phoneNumber = listItem.dataset.number;
        try {
            const data = await apiRequest(`/api/blocklist/${phoneNumber}`, 'DELETE');
            if (data.success) {
                listItem.remove();
            }
        } catch (error) {
            console.error('Erro ao desbloquear contato:', error);
        }
    }
});

document.addEventListener('DOMContentLoaded', () => {
    const params = new URLSearchParams(window.location.search);
    const token = params.get('token');

    if (token) {
        localStorage.setItem('accessToken', token);
        window.history.replaceState({}, document.title, window.location.pathname);
        showAppSection();
    } else if (getToken()) {
        showAppSection();
    } else {
        showLoginSection();
    }
});

function showAppSection() {
    loginSection.classList.add('hidden');
    appSection.classList.remove('hidden');
    fetchStatus();
    fetchPersona();
    loadBlocklist();
}

function showLoginSection() {
    loginSection.classList.remove('hidden');
    appSection.classList.add('hidden');
    localStorage.removeItem('accessToken');
}

connectBtn.addEventListener('click', async () => {
    connectBtn.textContent = 'Gerando QR Code...';
    connectBtn.disabled = true;
    try {
        const data = await apiRequest('/api/sessions/start', 'POST');
        if (data.success && data.qrCodeDataUrl) {
            qrContainer.innerHTML = `<img src="${data.qrCodeDataUrl}" alt="QR Code">`;
        } else if (data.message) {
            alert(data.message);
        }
    } catch (error) {
        console.error('Erro ao iniciar sessão:', error);
    } finally {
        connectBtn.textContent = 'Conectar WhatsApp';
        connectBtn.disabled = false;
    }
});