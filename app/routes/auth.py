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
    # 1. Busca o token nos cookies
    token = request.cookies.get("access_token")

    if not token:
        raise HTTPException(
            status_code=401, 
            detail="Não autenticado. Por favor, faça login."
        )

    # 2. Verifica a Blacklist (Logout)
    token_banido = db.query(database.TokenBlacklist).filter(database.TokenBlacklist.token == token).first()

    if token_banido:
        raise HTTPException(
            status_code=401, 
            detail="Sessão encerrada. Faça login novamente."
        )

    try:
        # 3. Decodifica o JWT e extrai os dados
        payload = jwt.decode(
            token, 
            security.SECRET_KEY, 
            algorithms=[security.ALGORITHM]
        )
    
        email: str = payload.get("sub")
        token_version = payload.get("version") # <--- EXTRAI A VERSÃO DO TOKEN

        if email is None: 
            raise HTTPException(status_code=401, detail="Token inválido")

    except JWTError:
        raise HTTPException(
            status_code=401, 
            detail="Sessão expirada. Faça login novamente."
        )
    
    # 4. Busca o usuário no banco de dados
    usuario = db.query(database.UsuarioDB).filter(database.UsuarioDB.email == email).first()

    if not usuario: 
        raise HTTPException(
            status_code=401, 
            detail="Usuário não encontrado"
        )
    
    # 5. COMPARAÇÃO DE SEGURANÇA (O pulo do gato)
    # Se a versão no token for diferente da versão no banco, a senha foi alterada
    if str(token_version) != str(usuario.senha_versao):
        raise HTTPException(
            status_code=401, 
            detail="Senha alterada em outro dispositivo. Por segurança, faça login novamente."
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
@limiter.limit("5/minute")
async def login(
    request: Request,
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
    token = security.criar_token_acesso(
        dados={
            "sub": usuario.email,
            "version": usuario.senha_versao
        }
    )

    # 5. GERAR O COOKIE (A mágica da segurança)
    response.set_cookie(
        key="access_token", 
        value=token, 
        httponly=True,   # JavaScript não acessa! (Protege contra XSS)
        max_age=1800,    # 30 minutos
        samesite="lax",  # Protege contra CSRF
        secure=False,
        path="/"     # Mude para True se usar HTTPS (o navegador exige)
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
        link_recuperacao = f"http://localhost:5173/reset-password?token={token}"
        print(f"\n--- E-MAIL ENVIADO PARA {usuario.email} --\nLink: {link_recuperacao}\n----------------\n")
    return{
        "msg": "Se o e-mail existir, um link de recuperação foi enviado."
    }

@router.post("/resetar-senha")
async def resetar_senha(dados: schemas.ResetarSenha, db: Session = Depends(get_db)):
    # 1. Verificar se o TOKEN já foi usado anteriormente (Segurança contra reuso)
    token_na_blacklist = db.query(database.TokenBlacklist).filter(database.TokenBlacklist.token == dados.token).first()
    if token_na_blacklist:
        raise HTTPException(status_code=400, detail="Este link de recuperação já foi utilizado.")

    try:
        # 2. Valida o Token JWT
        payload = jwt.decode(dados.token, security.SECRET_KEY, algorithms=[security.ALGORITHM])

        # 3. Verifica o propósito do token
        if payload.get("purpose") != "password_recovery":
            raise HTTPException(status_code=400, detail="Token inválido para esta operação")
        
        email = payload.get("sub")

        # 4. Busca o usuário
        usuario = db.query(database.UsuarioDB).filter(database.UsuarioDB.email == email).first()
        if not usuario:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")
        
        # --- ATUALIZAÇÃO SEGURA ---
        
        # Atualiza a senha
        usuario.senha_hash = security.gerar_hash_senha(dados.nova_senha)
        
        # INVALIDA SESSÕES ATIVAS: Muda a versão da senha
        # Isso fará com que qualquer token antigo (com versão velha) seja rejeitado
        usuario.senha_versao = str(datetime.utcnow().timestamp()) 
        
        # Resetar bloqueios de tentativas
        usuario.tentativas_erradas = 0 
        usuario.bloqueado_ate = None

        # 5. Adiciona o TOKEN DE RESET na Blacklist (Impede reuso)
        novo_banido = database.TokenBlacklist(token=dados.token)
        db.add(novo_banido)

        db.commit()
        
        return {
            "msg": "Senha alterada com sucesso! Todas as sessões antigas foram encerradas."
        }
    
    except JWTError:
        raise HTTPException(
            status_code=400,
            detail="Token de recuperação inválido ou expirado."
        )
    
@router.get("/admin/users")
async def listar_usuarios_admin(
    usuario_atual: database.UsuarioDB = Depends(obter_usuario_atual),
    db: Session = Depends(get_db)
):
    # Verificação do Nível de Acesso
    if usuario_atual.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Acesso proibido: Você não é um administrador."
        )
    
    usuarios = db.query(database.UsuarioDB).all()
    # Retornamos dados úteis para o painel
    return[
        {
            "id": u.id,
            "email": u.email,
            "role": u.role,
            "tentativas": u.tentativas_erradas,
            "bloqueado": u.bloqueado_ate is not None and u.bloqueado_ate > datetime.utcnow()
        } for u in usuarios
    ]

# Adicione esta rota ao final do seu arquivo auth.py

@router.post("/trocar-senha-perfil")
async def trocar_senha_perfil(
    dados: schemas.TrocarSenhaLogado,
    db: Session = Depends(get_db),
    usuario_atual: database.UsuarioDB = Depends(obter_usuario_atual)
):
    # 1. Verificar senha atual
    if not security.verificar_senha(dados.senha_atual, usuario_atual.senha_hash):
        raise HTTPException(status_code=400, detail="Senha atual incorreta")

    # 2. Atualizar senha e versão (para deslogar outros)
    usuario_atual.senha_hash = security.gerar_hash_senha(dados.nova_senha)
    usuario_atual.senha_versao = str(datetime.utcnow().timestamp())
    
    db.commit()
    return {"msg": "Senha alterada com sucesso! Faça login novamente."}