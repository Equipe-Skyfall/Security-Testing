"""Configuracoes da API.

ATENCAO: versao VULNERAVEL de proposito (branch vulneravel). Nao use em producao.
"""
import os

# FALHA: segredo do JWT fixo no codigo e fraco (facil de adivinhar com uma wordlist).
JWT_SECRET = "segredo123"
JWT_ALGORITHM = "HS256"
JWT_EXPIRACAO_MINUTOS = 60 * 24 * 30

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./notas.db")
