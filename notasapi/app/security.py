"""Senhas, tokens JWT, controle de acesso e limite de tentativas de login."""
import time
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app import config
from app.database import get_db
from app.models import Usuario

bearer = HTTPBearer(auto_error=False)


def gerar_hash_senha(senha: str) -> str:
    # bcrypt gera um salt aleatorio por senha e e propositalmente lento.
    return bcrypt.hashpw(senha.encode(), bcrypt.gensalt()).decode()


def verificar_senha(senha: str, senha_hash: str) -> bool:
    return bcrypt.checkpw(senha.encode(), senha_hash.encode())


def criar_token(usuario: Usuario) -> str:
    agora = datetime.now(timezone.utc)
    payload = {
        "sub": str(usuario.id),
        "papel": usuario.papel,
        "iat": agora,
        "exp": agora + timedelta(minutes=config.JWT_EXPIRACAO_MINUTOS),
    }
    return jwt.encode(payload, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)


def _nao_autenticado() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token ausente ou invalido",
        headers={"WWW-Authenticate": "Bearer"},
    )


def usuario_atual(
    credenciais: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> Usuario:
    if credenciais is None:
        raise _nao_autenticado()
    try:
        # Lista fixa de algoritmos (bloqueia "none") e verificacao de assinatura e expiracao.
        payload = jwt.decode(
            credenciais.credentials,
            config.JWT_SECRET,
            algorithms=[config.JWT_ALGORITHM],
            options={"require": ["sub", "exp"]},
        )
        usuario = db.get(Usuario, int(payload["sub"]))
    except (jwt.PyJWTError, ValueError):
        raise _nao_autenticado()
    if usuario is None:
        raise _nao_autenticado()
    return usuario


def exigir_papel(papel: str):
    """Autorizacao por funcao: o papel vem do banco, nunca do corpo da requisicao."""

    def verificar(usuario: Usuario = Depends(usuario_atual)) -> Usuario:
        if usuario.papel != papel:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Acesso negado")
        return usuario

    return verificar


class LimitadorLogin:
    """Bloqueia o login de um e-mail apos N senhas erradas dentro de uma janela de tempo."""

    def __init__(self, max_tentativas: int, janela_segundos: int):
        self.max_tentativas = max_tentativas
        self.janela_segundos = janela_segundos
        self._falhas: dict[str, list[float]] = {}

    def _recentes(self, chave: str) -> list[float]:
        limite = time.monotonic() - self.janela_segundos
        falhas = [t for t in self._falhas.get(chave, []) if t > limite]
        self._falhas[chave] = falhas
        return falhas

    def bloqueado(self, chave: str) -> bool:
        return len(self._recentes(chave)) >= self.max_tentativas

    def registrar_falha(self, chave: str) -> None:
        self._recentes(chave).append(time.monotonic())

    def limpar(self, chave: str | None = None) -> None:
        if chave is None:
            self._falhas.clear()
        else:
            self._falhas.pop(chave, None)


limitador_login = LimitadorLogin(config.LOGIN_MAX_TENTATIVAS, config.LOGIN_JANELA_SEGUNDOS)
