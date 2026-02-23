from pydantic import BaseModel, EmailStr, Field

# Esquema para criar usuário(O que o usuário envia)
class UsuarioCreate(BaseModel):
    email: EmailStr # Valida se é um e-mail real
    senha: str = Field (..., min_length=8, max_length=100, description="A senha deve ter no mínimo 8 caracteres")

# Esquema para responder ao front (O que a API devolve)
class UsuarioPublico(BaseModel):
    id: int
    email: EmailStr

    class Config:
        from_attributes = True # Permite que o pydantic leia dados do SQLAlchemy

class RecuperarSenhaRequest(BaseModel):
    email: EmailStr

class ResetarSenha(BaseModel):
    token: str
    nova_senha: str = Field(..., min_length=8, description="A senha deve ter no mínimo 8 caracteres")