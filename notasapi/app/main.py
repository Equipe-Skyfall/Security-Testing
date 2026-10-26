from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

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
    description="API de gestao de notas academicas - versao VULNERAVEL (branch vulneravel). Nao use em producao.",
    version="0.1.0",
    lifespan=lifespan,
)

# FALHA: CORS liberado para qualquer origem e nenhum cabecalho de seguranca nas respostas.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
