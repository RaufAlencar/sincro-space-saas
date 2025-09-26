Sincro Space - Clone Digital


-----

````markdown
# Sincro.space



**Seu Clone Digital no WhatsApp - Automatize, Responda e Venda 24/7**

[![Status do Projeto](https://img.shields.io/badge/status-ativo-success)](https://app-sincro-space.onrender.com)
[![Linguagem](https://img.shields.io/badge/language-JavaScript-yellow)](https://developer.mozilla.org/pt-BR/docs/Web/JavaScript)
[![Licença](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

---

### 📖 Sobre o Projeto

Você já perdeu um cliente ou uma oportunidade de negócio porque não conseguiu responder uma mensagem no WhatsApp a tempo? O Sincro.space nasceu para resolver esse problema.

Sincro.space é uma plataforma SaaS (Software as a Service) que cria um **clone digital inteligente** de você. Conectado diretamente ao seu WhatsApp, ele utiliza a IA do Google Gemini para entender, interagir e responder aos seus contatos como se fosse você, 24 horas por dia, 7 dias por semana.



---

### ✨ Principais Funcionalidades

* **🤖 Persona de IA 100% Customizável:** Defina a personalidade, o tom de voz e o conhecimento do seu clone digital através de um simples painel de controle.
* **⏰ Automação de Respostas 24/7:** Garanta que nenhum cliente fique sem resposta, mesmo quando você está dormindo, em reuniões ou de férias.
* **📈 CRM Integrado e Automático:** Todo novo contato que envia uma mensagem é salvo automaticamente no seu painel, permitindo a adição de tags e gerenciamento.
* **🚫 Gerenciamento de Contatos Bloqueados:** Crie uma blocklist para evitar que o bot interaja com contatos indesejados.
* **💻 Painel de Controle Web Intuitivo:** Gerencie a persona, os contatos e a conexão com o WhatsApp de qualquer lugar através de uma interface web simples e segura.

---

### 🛠️ Tecnologias Utilizadas

Este projeto foi construído com uma stack moderna e robusta, focada em escalabilidade e performance.

* **Backend:** Node.js, Express.js
* **Inteligência Artificial:** Google Gemini API
* **Integração com WhatsApp:** `whatsapp-web.js` (utilizando Puppeteer)
* **Banco de Dados:** PostgreSQL (gerenciado pelo Supabase)
* **Autenticação:** Google OAuth 2.0 e JSON Web Tokens (JWT)
* **Frontend:** HTML5, CSS3, JavaScript (Vanilla)
* **Hospedagem:** Render (Backend) e Vercel (Frontend)

---

### 🚀 Configuração e Instalação

Para rodar este projeto localmente, siga os passos abaixo:

1.  **Clone o repositório:**
    ```bash
    git clone [https://github.com/SEU_USUARIO/SEU_REPOSITORIO.git](https://github.com/SEU_USUARIO/SEU_REPOSITORIO.git)
    ```

2.  **Navegue até o diretório do projeto:**
    ```bash
    cd sincro-space-saas
    ```

3.  **Instale as dependências:**
    ```bash
    npm install
    ```

4.  **Crie e configure as variáveis de ambiente:**
    * Crie uma cópia do arquivo de exemplo `.env.example` e renomeie para `.env`.
    * Preencha todas as variáveis com as suas chaves e credenciais.

5.  **Inicie o servidor:**
    ```bash
    npm start
    ```
    O servidor estará rodando em `http://localhost:3000`.

---

### 🔑 Variáveis de Ambiente

Para que a aplicação funcione, você precisará criar um arquivo `.env` na raiz do projeto com as seguintes variáveis:

```env
# Banco de Dados (Supabase)
DATABASE_URL="Sua_connection_string_do_Supabase"

# JSON Web Token
JWT_SECRET="Seu_segredo_super_secreto_para_o_jwt"

# Google AI (Gemini)
GEMINI_API_KEY="Sua_chave_de_API_do_Google_Gemini"

# Google OAuth 2.0
GOOGLE_CLIENT_ID="Seu_Client_ID_do_Google_Cloud"
GOOGLE_CLIENT_SECRET="Seu_Client_Secret_do_Google_Cloud"

# URLs da Aplicação
FRONTEND_URL="URL_onde_seu_frontend_esta_hospedado"
BACKEND_URL="URL_do_seu_servidor_no_Render"
````

-----

### ☁️ Deploy

O backend desta aplicação está configurado para deploy na **Render**, utilizando Discos Persistentes para garantir a continuidade da sessão do WhatsApp. O banco de dados é gerenciado pelo **Supabase**.

O frontend pode ser hospedado em qualquer serviço de sites estáticos, como Vercel, Netlify ou Render Static Sites.

-----

### 👨‍💻 Autor

**Rauf Alencar de Oliveira**

  
  * [GitHub](https://www.google.com/search?q=https://github.com/RaufAlencar)

<!-- end list -->

```
```