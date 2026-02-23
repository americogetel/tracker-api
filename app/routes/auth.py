from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from jose import jwt, JWTError
from slowapi import Limiter
from slowapi.util import get_remote_address
from datetime import datetime
import app.database as database
import app.security as security
import app.schemas as schemas

# Criamos o Router (como se fosse um mini-app)
router = APIRouter(tags=["Autenticação"])

# Recuperamos o limitador (ou criamos um local)
limiter = Limiter(key_func=get_remote_address)

# Dependência do Banco de Dados (copiada do main)
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def obter_usuario_atual(request: Request, db: Session = Depends(get_db)):
    # 1. Tenta buscar o token dentro dos cookies do navegador
    token = request.cookies.get("access_token")

    # Se o cookie não existir, o usuário não está logado
    if not token:
        raise HTTPException(
            status_code=401, 
            detail="Não autenticado. Por favor, faça login."
        )

    # 2. Verificar se o token está na blacklist (mesma lógica)
    token_banido = db.query(database.TokenBlacklist).filter(database.TokenBlacklist.token == token).first()

    if token_banido:
        raise HTTPException(
            status_code=401, 
            detail="Token inválido (Logout já realizado)"
        )

    try:
        # 3. Decodificar o JWT
        payload = jwt.decode(
            token, 
            security.SECRET_KEY, 
            algorithms=[security.ALGORITHM]
        )
    
        email: str = payload.get("sub")
        if email is None: 
            raise HTTPException(status_code=401, detail="Token inválido")

    except JWTError:
        raise HTTPException(
            status_code=401, 
            detail="Sessão expirada. Faça login novamente."
        )
    
    # 4. Buscar o usuário no banco
    usuario = db.query(database.UsuarioDB).filter(database.UsuarioDB.email == email).first()

    if not usuario: 
        raise HTTPException(
            status_code=401, 
            detail="Usuário não encontrado"
        )
        
    return usuario

# --- ROTAS (Agora usamos @router em vez de @app) ---

@router.post("/register", response_model=schemas.UsuarioPublico, status_code=status.HTTP_201_CREATED)
async def register(usuario: schemas.UsuarioCreate, db: Session = Depends(get_db)):

    usuario_existente = db.query(database.UsuarioDB).filter(database.UsuarioDB.email == usuario.email).first()

    if usuario_existente:
        raise HTTPException(
            status_code=400, 
            detail="Este e-mail já está em uso."
        )
    
    novo_usuario = database.UsuarioDB(email=usuario.email, senha_hash=security.gerar_hash_senha(usuario.senha))

    db.add(novo_usuario)
    db.commit()
    db.refresh(novo_usuario)
    return novo_usuario

@router.post("/login")
async def login(
    response: Response, # Adicionado para carimbar o cookie
    form_data: OAuth2PasswordRequestForm = Depends(), 
    db: Session = Depends(get_db)
):
    usuario = db.query(database.UsuarioDB).filter(database.UsuarioDB.email == form_data.username).first()
    
    # Validação inicial de existência
    if not usuario:
        raise HTTPException(status_code=401, detail="E-mail ou senha inválidos")

    # 1. Verificar tempo de bloqueio (Lógica mantida)
    if usuario.bloqueado_ate and datetime.utcnow() < usuario.bloqueado_ate:
        tempo_restante = (usuario.bloqueado_ate - datetime.utcnow()).seconds // 60
        raise HTTPException(
            status_code=403, 
            detail=f"Muitas tentativas. Tente novamente em {tempo_restante + 1} minutos."
        )

    # 2. Verificar a senha
    senha_correta = security.verificar_senha(form_data.password, usuario.senha_hash)

    if not senha_correta:
        usuario.tentativas_erradas += 1
        usuario.bloqueado_ate = security.calcular_tempo_bloqueio(usuario.tentativas_erradas)
        db.commit()
        raise HTTPException(status_code=401, detail="E-mail ou senha inválidos")

    # 3. Sucesso: Resetar contadores
    usuario.tentativas_erradas = 0
    usuario.bloqueado_ate = None
    db.commit()

    # 4. Criar o Token
    token = security.criar_token_acesso(dados={"sub": usuario.email})

    # 5. GERAR O COOKIE (A mágica da segurança)
    response.set_cookie(
        key="access_token", 
        value=token, 
        httponly=True,   # JavaScript não acessa! (Protege contra XSS)
        max_age=1800,    # 30 minutos
        samesite="lax",  # Protege contra CSRF
        secure=False     # Mude para True se usar HTTPS (o navegador exige)
    )

    return {"msg": "Login realizado com sucesso"}

@router.post("/logout")
async def logout(
    response: Response, 
    usuario_atual: database.UsuarioDB = Depends(obter_usuario_atual), # Já valida o cookie aqui
    db: Session = Depends(get_db),
    request: Request = None # Para pegar o token bruto
):
    # Pegamos o token do cookie para colocar na blacklist
    token = request.cookies.get("access_token")
    
    if token:
        novo_token_banido = database.TokenBlacklist(token=token)
        db.add(novo_token_banido)
        db.commit()

    response.delete_cookie("access_token")
    return {"msg": "Logout realizado com sucesso e token invalidado."}

@router.post("/esqueci-minha-senha")
async def esqueci_senha(dados: schemas.RecuperarSenhaRequest, db: Session = Depends(get_db)):
    usuario = db.query(database.UsuarioDB).filter(database.UsuarioDB.email == dados.email).first()

    # Segurança: Mesmo que o e-mail não exista, respondemos a mesma coisa
    # para evitar que hackers descubram quais e-mails estão cadastrados.

    if usuario:
        token = security.criar_token_recuperacao(usuario.email)
        # Aqui enviaremos o e-mail real. Por enquanto vamos simular:
        link_recuperacao = f"https://127.0.0.1:8000/auth/resetar-senha?token={token}"
        print(f"\n--- E-MAIL ENVIADO PARA {usuario.email} --\nLink: {link_recuperacao}\n----------------\n")
    return{
        "msg": "Se o e-mail existir, um link de recuperação foi enviado."
    }

@router.post("/resetar-senha")
async def resetar_senha(dados: schemas.ResetarSenha, db: Session = Depends(get_db)):
    try:
        # 1. Valida o Token
        payload = jwt.decode(dados.token, security.SECRET_KEY, algorithms=[security.ALGORITHM])

        # 2. Verifica se o propósito do token é recuperação
        if payload.get("purpose") != "password_recovery":
            raise HTTPException(
                status_code=400,
                detail="Token inválido para esta operação"
            )
        
        email = payload.get("sub")

        # 3. Busca o usuário e atualiza a senha
        usuario = db.query(database.UsuarioDB).filter(database.UsuarioDB.email == email).first()
        if not usuario:
            raise HTTPException(
                status_code=404,
                detail="Usuário não encontrado"
            )
        
        usuario.senha_hash = security.gerar_hash_senha(dados.nova_senha)
        usuario.tentativas_erradas = 0 # Resetar bloqueios
        usuario.bloqueado_ate = None

        db.commit()
        return{
            "msg": "Senha alterada com sucesso! Agora você já pode fazer login."
        }
    
    except JWTError:
        raise HTTPException(
            status_code=400,
            detail="Token de recuperação inválido ou expirado."
        )