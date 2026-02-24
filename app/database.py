from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

URL_BANCO = "sqlite:///./usuarios.db"

engine = create_engine(
    URL_BANCO, 
    connect_args={"check_same_thread": False, "timeout": 30})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Tabela de Usuários
class UsuarioDB(Base):
    __tablename__ = "usuarios"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    senha_hash = Column(String)
    tentativas_erradas = Column(Integer, default=0)
    bloqueado_ate = Column(DateTime, nullable=True)
    senha_versao = Column(String, default=lambda: str(datetime.utcnow().timestamp()))
    role = Column(String, default="user")

class TokenBlacklist(Base):
    __tablename__ = "token_blacklist"
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, index=True)

# Criar as tabelas no arquivo .db
Base.metadata.create_all(bind=engine)