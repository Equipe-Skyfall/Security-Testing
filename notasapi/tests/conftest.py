"""Configuracao comum dos testes de seguranca.

Os mesmos testes rodam nas duas branches: na `vulneravel` eles FALHAM
(provando que a falha existe) e na `main` eles PASSAM (provando a correcao
e servindo de teste de regressao a cada commit).
"""
import os
import secrets
import tempfile
from datetime import datetime, timedelta, timezone

# As variaveis precisam existir antes de importar a aplicacao.
_pasta = tempfile.mkdtemp(prefix="notasapi-testes-")
os.environ["DATABASE_URL"] = f"sqlite:///{_pasta}/teste.db"
os.environ.setdefault("JWT_SECRET", secrets.token_hex(32))

import jwt  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import config  # noqa: E402
from app import security  # noqa: E402
from app.database import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Usuario  # noqa: E402
from app.seed import popular_banco  # noqa: E402

SENHAS = {
    "carla@escola.br": "Professora@2026",
    "ana@escola.br": "AnaAluna@2026",
    "bruno@escola.br": "BrunoAluno@2026",
}


@pytest.fixture
def client():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        popular_banco(db)
    # O limitador de login so existe na versao corrigida.
    limitador = getattr(security, "limitador_login", None)
    if limitador is not None:
        limitador.limpar()
    # Erros internos viram respostas HTTP 500 (como um cliente real veria), e nao excecoes no teste.
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


def usuario_por_email(email: str) -> Usuario:
    with SessionLocal() as sessao:
        usuario = sessao.query(Usuario).filter(Usuario.email == email).one()
        sessao.expunge(usuario)
        return usuario


def login(client: TestClient, email: str) -> str:
    resposta = client.post("/auth/login", json={"email": email, "senha": SENHAS[email]})
    assert resposta.status_code == 200, resposta.text
    return resposta.json()["access_token"]


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def forjar_token(usuario: Usuario, papel: str | None = None, segredo: str | None = None,
                 algoritmo: str = "HS256", expira_em: timedelta = timedelta(minutes=30)) -> str:
    """Gera um token como um atacante faria (PyJWT), com o formato de payload das duas versoes."""
    payload = {
        "sub": str(usuario.id),
        "id": usuario.id,
        "papel": papel or usuario.papel,
        "exp": datetime.now(timezone.utc) + expira_em,
    }
    chave = config.JWT_SECRET if segredo is None else segredo
    if algoritmo == "none":
        return jwt.encode(payload, None, algorithm="none")
    return jwt.encode(payload, chave, algorithm=algoritmo)
