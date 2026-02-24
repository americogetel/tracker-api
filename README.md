# 🔐 Tracker API

API de autenticação robusta, segura e escalável desenvolvida com **FastAPI**, focada em **segurança**, **performance** e **experiência do desenvolvedor**.

---

## 🚀 Funcionalidades

### 👤 Autenticação & Usuários

- ✅ Cadastro com validação rigorosa de e-mail
- 🔒 Política de senha forte (Regex)
- 🍪 Login seguro via **Cookies HttpOnly + SameSite**
- 🚪 Logout com blacklist de tokens
- 🔁 Invalidação global de sessões ao alterar senha (versionamento de token)

### 🛡️ Segurança Avançada

- 🧱 Proteção contra **Brute-Force** (bloqueio progressivo)
- ⏳ Tokens temporários de uso único para recuperação de senha
- 🏷️ Controle de acesso baseado em função (**RBAC**: `user` e `admin`)
- 🚦 Rate Limiting em endpoints sensíveis
- 🔐 JWT seguro com expiração configurável

---

## 🛠️ Stack Tecnológica

| Camada             | Tecnologia                                       |
| ------------------ | ------------------------------------------------ |
| **Backend**        | Python 3.10+ & FastAPI                           |
| **Banco de Dados** | SQLAlchemy + SQLite _(portável para PostgreSQL)_ |
| **Autenticação**   | JWT (JSON Web Tokens)                            |
| **Criptografia**   | Passlib (Bcrypt)                                 |
| **Tokens**         | Python-Jose                                      |
| **Rate Limiting**  | SlowAPI                                          |

---

## 📦 Instalação e Execução

### 1️⃣ Clone o repositório

```bash
git clone https://github.com/seu-usuario/tracker-api.git
cd tracker-api
```

### 2 Criar e Ativar Ambiente Virtual

```bash
python -m venv .venv
.venv\Scripts\active
```

### 3 Instalar Dependências

```bash
pip install -r requirements.txt
```

### 4

SECRET_KEY=sua_chave_secreta_super_segura
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

### 5

```bash
uvicorn app.main:app --reload
```

## 🏗️ Estrutura do Projeto

-- app/auth.py: Rotas e lógica principal de autenticação.

-- app/database.py: Modelos do SQLAlchemy e conexão com o banco.

-- app/security.py: Funções auxiliares de hash, criação de tokens e lógica de bloqueio.

-- app/schemas.py: Schemas do Pydantic para validação de entrada/saída de dados.
