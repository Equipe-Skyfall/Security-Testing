"""Senhas, tokens JWT e controle de acesso.

ATENCAO: versao VULNERAVEL de proposito (branch vulneravel). Nao use em producao.
"""
import hashlib
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app import config
from app.database import get_db
from app.models import Usuario

bearer = HTTPBearer(auto_error=False)


def gerar_hash_senha(senha: str) -> str:
    # FALHA: MD5 sem salt - senhas iguais geram o mesmo hash e sao quebradas em segundos.
    return hashlib.md5(senha.encode()).hexdigest()


def verificar_senha(senha: str, senha_hash: str) -> bool:
    return gerar_hash_senha(senha) == senha_hash


def criar_token(usuario: Usuario) -> str:
    payload = {
        "id": usuario.id,
        "papel": usuario.papel,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=config.JWT_EXPIRACAO_MINUTOS),
    }
    return jwt.encode(payload, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)


def usuario_atual(
    credenciais: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> Usuario:
    if credenciais is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token ausente")
    try:
        # FALHA: a assinatura (e, com ela, a expiracao) nao e verificada.
        # Qualquer token bem formado e aceito, inclusive com alg "none" ou segredo errado.
        payload = jwt.decode(
            credenciais.credentials,
            config.JWT_SECRET,
            algorithms=["HS256", "none"],
            options={"verify_signature": False},
        )
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invalido")
    usuario = db.get(Usuario, payload.get("id"))
    if usuario is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuario nao encontrado")
    # FALHA: o papel e lido do token (controlado pelo cliente), nao do banco.
    usuario.papel = payload.get("papel", usuario.papel)
    return usuario
