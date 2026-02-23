from fastapi import APIRouter, Depends
import app.database as database
from .auth import obter_usuario_atual # Importamos a validação que criamos acima

router = APIRouter(tags=["Conteúdo"])

@router.get("/home")
async def home(usuario_atual: database.UsuarioDB = Depends(obter_usuario_atual)):
    return {
        "info": "Acesso autorizado!",
        "usuario_email": usuario_atual.email,
        "mensagem": "Este dado veio de um módulo separado!"
    }