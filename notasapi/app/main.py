from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app import config
from app.database import Base, SessionLocal, engine
from app.routes import router
from app.seed import popular_banco


@asynccontextmanager
async def lifespan(_app: FastAPI):
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        popular_banco(db)
    yield


app = FastAPI(
    title="NotasAPI",
    description="API de gestao de notas academicas - versao CORRIGIDA (branch main).",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if config.EXPOR_DOCS else None,
    redoc_url=None,
    openapi_url="/openapi.json" if config.EXPOR_DOCS else None,
)

# CORS restrito a origens conhecidas (nunca "*").
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGENS,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def cabecalhos_de_seguranca(request: Request, call_next):
    resposta = await call_next(request)
    resposta.headers["X-Content-Type-Options"] = "nosniff"
    resposta.headers["X-Frame-Options"] = "DENY"
    resposta.headers["Referrer-Policy"] = "no-referrer"
    resposta.headers["Cache-Control"] = "no-store"
    resposta.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    resposta.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    # O Swagger UI (/docs) carrega scripts externos; o restante da API nao carrega nada.
    if request.url.path != "/docs":
        resposta.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    return resposta


app.include_router(router)
