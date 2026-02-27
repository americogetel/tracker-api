from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes import auth, home # Importamos nossos novos arquivos
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Define o limitador usando o endereço IP do usuário
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="Meu Sistema Modular")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5500",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# A MÁGICA ACONTECE AQUI:
app.include_router(auth.router) # Inclui as rotas de login/register/logout
app.include_router(home.router) # Inclui a rota home