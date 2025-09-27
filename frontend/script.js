const API_BASE_URL = 'https://app-sincro-v2.onrender.com';

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
const contactList = document.getElementById('contact-list');

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

async function loadContacts() {
    try {
        const data = await apiRequest('/api/contacts');
        contactList.innerHTML = '';
        if (data.success) {
            data.contacts.forEach(renderContact);
        }
    } catch (error) {
        console.error('Erro ao carregar contatos:', error);
    }
}

function renderBlockedContact(phoneNumber) {
    const li = document.createElement('li');
    li.dataset.number = phoneNumber;
    li.innerHTML = `<span>${phoneNumber}</span><button class="unblock-btn">&times;</button>`;
    blockList.appendChild(li);
}

function renderContact(contact) {
    const li = document.createElement('li');
    li.dataset.id = contact.id;
    const tags = contact.tags || [];
    const tagsHTML = tags.map(tag => `<span class="tag">${tag}</span>`).join('');
    
    li.innerHTML = `
        <div class="contact-info">${contact.name}</div>
        <div class="contact-number">${contact.phone_number}</div>
        <div class="tags-display">${tagsHTML}</div>
        <form class="tags-form">
            <input type="text" class="tags-input" placeholder="cliente, vip, etc" value="${tags.join(', ')}">
            <button type="submit">Salvar</button>
        </form>
    `;
    contactList.appendChild(li);
}

savePersonaBtn.addEventListener('click', async () => {
    try {
        const data = await apiRequest('/api/config/persona', 'PUT', { persona: personaTextarea.value });
        if (data.success) {
            saveFeedback.textContent = 'Persona salva com sucesso!';
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

contactList.addEventListener('click', async (e) => {
    if (e.target.tagName === 'BUTTON' && e.target.closest('form').classList.contains('tags-form')) {
        e.preventDefault();
        const form = e.target.closest('form');
        const listItem = form.closest('li');
        const contactId = listItem.dataset.id;
        const tagsInput = form.querySelector('.tags-input');
        const tags = tagsInput.value.split(',').map(tag => tag.trim()).filter(Boolean);
        
        try {
            const data = await apiRequest(`/api/contacts/${contactId}`, 'PUT', { tags });
            if (data.success) {
                const tagsDisplay = listItem.querySelector('.tags-display');
                tagsDisplay.innerHTML = tags.map(tag => `<span class="tag">${tag}</span>`).join('');
                alert('Tags salvas!');
            }
        } catch (error) {
            console.error('Erro ao atualizar tags:', error);
        }
    }
});

connectBtn.addEventListener('click', async () => {
    connectBtn.textContent = 'Gerando QR Code...';
    connectBtn.disabled = true;
    qrContainer.innerHTML = '';
    try {
        const data = await apiRequest('/api/sessions/start', 'POST');
        if (data.success && data.qrCodeDataUrl) {
            qrContainer.innerHTML = `<img src="${data.qrCodeDataUrl}" alt="QR Code">`;
            connectBtn.classList.add('hidden');
        } else if (data.message) {
            alert(data.message);
        }
    } catch (error) {
        console.error('Erro ao iniciar sessão:', error);
    } finally {
        connectBtn.textContent = 'Conectar WhatsApp';
        connectBtn.disabled = false;
        if (!qrContainer.hasChildNodes()){
            connectBtn.classList.remove('hidden');
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
    loadContacts();
    setInterval(fetchStatus, 5000); 
}

function showLoginSection() {
    loginSection.classList.remove('hidden');
    appSection.classList.add('hidden');
    localStorage.removeItem('accessToken');
}