from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv
from datetime import datetime, timedelta
import os

load_dotenv()

# Configurações Críticas
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def gerar_hash_senha(senha: str):
    return pwd_context.hash(senha)

def verificar_senha(senha_pura, senha_hash):
    return pwd_context.verify(senha_pura, senha_hash)

def criar_token_acesso(dados: dict):
    para_codificar = dados.copy()
    expiracao = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    para_codificar.update({"exp": expiracao})
    return jwt.encode(para_codificar, SECRET_KEY, algorithm=ALGORITHM)

def criar_token_recuperacao(email: str):
    expiracao = datetime.utcnow() + timedelta(minutes=15) # Expira rápido por segurança
    payload = {
        "sub": email,
        "exp": expiracao,
        "purpose": "password_recovery"
    }

    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def calcular_tempo_bloqueio(tentativas: int):
    if tentativas < 3:
        return None
    if tentativas == 3:
        return datetime.utcnow() + timedelta(minute=1)
    if tentativas == 4:
        return datetime.utcnow() + timedelta(minute=5)
    return datetime.utcnow() + timedelta(minute=30)