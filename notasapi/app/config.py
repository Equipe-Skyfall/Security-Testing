"""Configuracoes lidas de variaveis de ambiente (nunca fixas no codigo)."""
import os

JWT_SECRET = os.environ.get("JWT_SECRET", "")
if len(JWT_SECRET) < 32:
    raise RuntimeError(
        "Defina a variavel de ambiente JWT_SECRET com pelo menos 32 caracteres "
        "(ex.: python -c \"import secrets; print(secrets.token_hex(32))\")."
    )

JWT_ALGORITHM = "HS256"
JWT_EXPIRACAO_MINUTOS = int(os.environ.get("JWT_EXPIRACAO_MINUTOS", "30"))

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./notas.db")

# Origens autorizadas a chamar a API pelo navegador (CORS), separadas por virgula.
CORS_ORIGENS = [o.strip() for o in os.environ.get("CORS_ORIGENS", "http://localhost:3000").split(",") if o.strip()]

# A documentacao interativa (/docs) so e exposta no ambiente de teste.
EXPOR_DOCS = os.environ.get("EXPOR_DOCS", "false").lower() == "true"

# Limite de tentativas de login com senha errada antes de bloquear (HTTP 429).
LOGIN_MAX_TENTATIVAS = int(os.environ.get("LOGIN_MAX_TENTATIVAS", "5"))
LOGIN_JANELA_SEGUNDOS = int(os.environ.get("LOGIN_JANELA_SEGUNDOS", "300"))
