import re
from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator

# --- Função Auxiliar de Validação (Para não repetir código) ---
def checar_senha_forte(v: str) -> str:
    if not re.search(r'[A-Z]', v):
        raise ValueError('A senha deve conter pelo menos uma letra maiúscula.')
    if not re.search(r'[a-z]', v):
        raise ValueError('A senha deve conter pelo menos uma letra minúscula.')
    if not re.search(r'\d', v):
        raise ValueError('A senha deve conter pelo menos um número.')
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
        raise ValueError('A senha deve conter pelo menos um caractere especial.')
    return v

class UsuarioCreate(BaseModel):
    email: EmailStr
    senha: str = Field(..., min_length=8, max_length=100)
    
    @field_validator('senha')
    @classmethod
    def validar(cls, v: str): return checar_senha_forte(v)

class UsuarioPublico(BaseModel):
    id: int
    email: EmailStr
    class Config: from_attributes = True

class RecuperarSenhaRequest(BaseModel):
    email: EmailStr

class ResetarSenha(BaseModel):
    token: str
    nova_senha: str = Field(..., min_length=8)
    confirmar_senha: str # Certifique-se que o nome é IGUAL ao usado no validador

    @field_validator('nova_senha')
    @classmethod
    def validar(cls, v: str): return checar_senha_forte(v)
    
    @model_validator(mode='after')
    def verificar_senhas_iguais(self):
        if self.nova_senha != self.confirmar_senha:
            raise ValueError('As senhas não coincidem')
        return self
    
class TrocarSenhaLogado(BaseModel):
    senha_atual: str
    nova_senha: str = Field(..., min_length=8)
    confirmar_nova_senha: str # Note o nome aqui

    @field_validator('nova_senha')
    @classmethod
    def validar(cls, v: str): return checar_senha_forte(v)
    
    @model_validator(mode='after')
    def verificar_senhas_iguais(self):
        # Ajustado para usar o nome correto do campo deste schema
        if self.nova_senha != self.confirmar_nova_senha:
            raise ValueError('As senhas não coincidem')
        return self