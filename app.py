# app.py
# =============================================================================
# FastAPI + SQLAlchemy + JWT - VERSÃO COM PERSISTÊNCIA DE CAMADAS
# =============================================================================

import os
import sys
import re
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from sqlalchemy import String, Integer, DateTime, func, select, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, declarative_base, relationship
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    async_sessionmaker,
    AsyncSession,
)

from passlib.context import CryptContext
from jose import jwt, JWTError

# =============================================================================
# Configurações de Ambiente (Sem alterações)
# =============================================================================

DATABASE_URL_RAW = os.getenv("DATABASE_URL", "").strip()
if not DATABASE_URL_RAW:
    raise RuntimeError("A variável de ambiente DATABASE_URL não foi definida.")

JWT_SECRET = os.getenv("JWT_SECRET", "super-secret-key-change-me")
JWT_ALG = "HS256"
JWT_EXPIRES_MIN = int(os.getenv("JWT_EXPIRES_MIN", "360"))

INIT_ADMIN = os.getenv("INIT_ADMIN", "true").lower() == "true"
INIT_ADMIN_USER = os.getenv("INIT_ADMIN_USER", "admin")
INIT_ADMIN_PASS = os.getenv("INIT_ADMIN_PASS", "123")

# =============================================================================
# Normalização de DATABASE_URL para asyncpg (Sem alterações)
# =============================================================================

u = urlparse(DATABASE_URL_RAW)
scheme = u.scheme or "postgresql"
if scheme == "postgresql":
    scheme = "postgresql+asyncpg"
elif scheme.startswith("postgresql+") and "asyncpg" not in scheme:
    scheme = "postgresql+asyncpg"

host = (u.hostname or "")
is_external = "." in host

qs = dict(parse_qsl(u.query or "", keep_blank_values=True))
qs.pop("sslmode", None)
qs.pop("ssl", None)

if is_external:
    qs["ssl"] = "true"

DATABASE_URL = urlunparse(u._replace(scheme=scheme, query=urlencode(qs)))

# =============================================================================
# Banco de Dados (SQLAlchemy 2.0 assíncrono)
# =============================================================================

Base = declarative_base()

# --- MODELO Layer MODIFICADO ---
# Esta classe representa a tabela 'layers' no banco de dados.
class Layer(Base):
    __tablename__ = "layers"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    type: Mapped[str] = mapped_column(String(50), default="vector")
    
    geojson_data: Mapped[str] = mapped_column(Text, nullable=False)
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    
    owner_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    
    owner: Mapped["User"] = relationship(back_populates="layers")
    
    # +++ ALTERAÇÃO (CORREÇÃO #2): Campo para Agrupamento de Camadas +++
    # Adicionamos um campo para o nome do grupo.
    # Ele é `nullable=True` porque uma camada pode não pertencer a nenhum grupo.
    group_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)


# --- MODELO User MODIFICADO ---
class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(150), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    
    layers: Mapped[List["Layer"]] = relationship(back_populates="owner", cascade="all, delete-orphan")


engine_kwargs = dict(echo=False, pool_pre_ping=True)
if is_external:
    engine_kwargs["connect_args"] = {"ssl": True}

engine = create_async_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

# =============================================================================
# Utilidades de Autenticação (Sem alterações)
# =============================================================================

def hash_password(password: str) -> str:
    return pwd_ctx.hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    return pwd_ctx.verify(password, password_hash)

def create_access_token(sub: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=JWT_EXPIRES_MIN)
    payload = {"sub": sub, "exp": expire}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def decode_access_token(token: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        sub: str = payload.get("sub")
        if sub is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido (sem sub).")
        return sub
    except JWTError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Token inválido: {str(e)}")

# =============================================================================
# Schemas (Pydantic)
# =============================================================================

# --- Schemas de Usuário (Sem grandes alterações) ---
class LoginIn(BaseModel):
    username: str
    password: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

class MeOut(BaseModel):
    id: int
    username: str
    created_at: datetime

# --- Schemas para Camadas (Layers) MODIFICADOS ---

class LayerBase(BaseModel):
    name: str
    type: str = "vector"
    geojson_data: str
    
    # +++ ALTERAÇÃO (CORREÇÃO #2): Campo para Agrupamento de Camadas +++
    # Adicionamos o campo opcional ao schema base para que ele possa ser recebido.
    group_name: Optional[str] = None

class LayerCreate(LayerBase):
    pass

class LayerOut(LayerBase):
    id: int
    created_at: datetime
    owner_id: int

    class Config:
        orm_mode = True

# =============================================================================
# App FastAPI (Sem alterações)
# =============================================================================

app = FastAPI(title="TerraSRF API", version="1.1.0", description="API para autenticação e persistência de dados GIS.")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# Startup / Shutdown (Sem alterações)
# =============================================================================

@app.on_event("startup")
async def startup() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    if INIT_ADMIN:
        async with SessionLocal() as session:
            res = await session.execute(select(User).where(User.username == INIT_ADMIN_USER))
            user = res.scalar_one_or_none()
            if not user:
                user = User(username=INIT_ADMIN_USER, password_hash=hash_password(INIT_ADMIN_PASS))
                session.add(user)
                await session.commit()
                print(f"[startup] Usuário admin criado: {INIT_ADMIN_USER}/{INIT_ADMIN_PASS}", file=sys.stderr)
            else:
                print("[startup] Usuário admin já existe; pulando criação.", file=sys.stderr)

# =============================================================================
# Dependências (Sem alterações)
# =============================================================================

async def get_db() -> AsyncSession:
    async with SessionLocal() as session:
        yield session

async def get_current_user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Header Authorization ausente ou mal formatado.")
    
    token = auth_header.split(" ", 1)[1].strip()
    username = decode_access_token(token)
    
    res = await db.execute(select(User).where(User.username == username))
    user = res.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuário do token não encontrado.")
        
    return user

# =============================================================================
# Rotas
# =============================================================================

# --- Rotas de Status e Autenticação (Sem alterações) ---

@app.get("/health", tags=["Status"])
async def health():
    return {"status": "ok"}

@app.post("/auth/login", response_model=TokenOut, tags=["Autenticação"])
async def login(body: LoginIn, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(User).where(User.username == body.username))
    user = res.scalar_one_or_none()

    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário ou senha inválidos."
        )
    
    token = create_access_token(sub=user.username)
    return TokenOut(access_token=token)


@app.get("/users/me", response_model=MeOut, tags=["Autenticação"])
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

# --- Rotas da API de Camadas (Layers) ---

@app.post("/api/layers/", response_model=LayerOut, status_code=status.HTTP_201_CREATED, tags=["Camadas"])
async def create_layer(
    layer: LayerCreate, 
    db: AsyncSession = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    """
    Cria uma nova camada no banco de dados, associada ao usuário logado.
    """
    db_layer = Layer(**layer.model_dump(), owner_id=current_user.id)
    db.add(db_layer)
    await db.commit()
    await db.refresh(db_layer)
    return db_layer

@app.get("/api/layers/", response_model=List[LayerOut], tags=["Camadas"])
async def get_user_layers(
    db: AsyncSession = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    """
    Retorna todas as camadas que pertencem ao usuário logado.
    """
    res = await db.execute(select(Layer).where(Layer.owner_id == current_user.id))
    layers = res.scalars().all()
    return layers

# Rota de UPDATE MODIFICADA
@app.put("/api/layers/{layer_id}", response_model=LayerOut, tags=["Camadas"])
async def update_layer(
    layer_id: int,
    layer_update: LayerCreate, # Reutilizamos o LayerCreate que agora tem o group_name
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Atualiza uma camada existente do usuário logado.
    """
    res = await db.execute(select(Layer).where(Layer.id == layer_id))
    db_layer = res.scalar_one_or_none()

    if not db_layer:
        raise HTTPException(status_code=404, detail="Camada não encontrada")

    if db_layer.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Acesso negado: você não é o dono desta camada.")

    # Atualiza os dados
    db_layer.name = layer_update.name
    db_layer.type = layer_update.type
    db_layer.geojson_data = layer_update.geojson_data
    
    # +++ ALTERAÇÃO (CORREÇÃO #2): Campo para Agrupamento de Camadas +++
    # Garantimos que o nome do grupo também seja atualizado no banco.
    db_layer.group_name = layer_update.group_name
    
    await db.commit()
    await db.refresh(db_layer)
    return db_layer

@app.delete("/api/layers/{layer_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Camadas"])
async def delete_layer(
    layer_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Deleta uma camada do usuário logado.
    """
    res = await db.execute(select(Layer).where(Layer.id == layer_id))
    db_layer = res.scalar_one_or_none()

    if db_layer and db_layer.owner_id == current_user.id:
        await db.delete(db_layer)
        await db.commit()
    
    return

@app.get("/", tags=["Status"])
async def root():
    return {"message": "API TerraSRF no ar. Use /docs para ver a documentação interativa."}

# =============================================================================
# Execução local (Sem alterações)
# =============================================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=True)