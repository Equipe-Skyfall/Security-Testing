"""OWASP API2:2023 - Broken Authentication / A02 e A07 do OWASP Top 10 (2021)."""
import base64
import hashlib
import json
from datetime import timedelta

from conftest import SENHAS, auth, forjar_token, usuario_por_email


def test_ct01_rota_protegida_sem_token_retorna_401(client):
    """CT01 - Requisicao a rota protegida sem token."""
    resposta = client.get("/notas/minhas")
    assert resposta.status_code == 401


def test_ct02_token_assinado_com_outro_segredo_retorna_401(client):
    """CT02 - Token assinado com um segredo diferente do da API."""
    ana = usuario_por_email("ana@escola.br")
    token = forjar_token(ana, segredo="segredo-do-atacante-com-mais-de-32-caracteres")
    resposta = client.get("/notas/minhas", headers=auth(token))
    assert resposta.status_code == 401


def test_ct02_token_assinado_com_segredo_fraco_adivinhado_retorna_401(client):
    """CT02 - Atacante tenta segredos comuns de uma wordlist (ataque de dicionario ao JWT)."""
    ana = usuario_por_email("ana@escola.br")
    for palpite in ["secret", "123456", "segredo", "segredo123", "senha", "changeme", "jwt-secret"]:
        token = forjar_token(ana, segredo=palpite)
        resposta = client.get("/notas/minhas", headers=auth(token))
        assert resposta.status_code == 401, f"A API aceitou um token assinado com o segredo '{palpite}'"


def test_ct03_token_com_algoritmo_none_retorna_401(client):
    """CT03 - Token sem assinatura (alg "none") se passando por professor."""
    ana = usuario_por_email("ana@escola.br")
    token = forjar_token(ana, papel="PROFESSOR", algoritmo="none")
    resposta = client.get("/notas/minhas", headers=auth(token))
    assert resposta.status_code == 401


def test_ct03_token_com_papel_alterado_no_payload_retorna_401(client):
    """CT03 - Token valido cujo payload foi editado (papel trocado) mantendo a assinatura original."""
    ana = usuario_por_email("ana@escola.br")
    cabecalho, payload, assinatura = forjar_token(ana).split(".")
    dados = json.loads(base64.urlsafe_b64decode(payload + "=="))
    dados["papel"] = "PROFESSOR"
    payload_adulterado = base64.urlsafe_b64encode(json.dumps(dados).encode()).decode().rstrip("=")
    token = f"{cabecalho}.{payload_adulterado}.{assinatura}"

    resposta = client.post("/notas", headers=auth(token),
                           json={"aluno_id": ana.id, "disciplina": "Historia", "valor": 10})
    assert resposta.status_code == 401


def test_ct04_token_expirado_retorna_401(client):
    """CT04 - Token assinado corretamente, mas com expiracao no passado."""
    ana = usuario_por_email("ana@escola.br")
    token = forjar_token(ana, expira_em=timedelta(minutes=-5))
    resposta = client.get("/notas/minhas", headers=auth(token))
    assert resposta.status_code == 401


def test_ct09_forca_bruta_no_login_retorna_429(client):
    """CT09 - Varias tentativas de login com senha errada devem ser bloqueadas."""
    for tentativa in range(5):
        resposta = client.post("/auth/login", json={"email": "ana@escola.br", "senha": f"chute{tentativa}"})
        assert resposta.status_code == 401
    # Mesmo acertando a senha, o atacante continua bloqueado ate o fim da janela.
    resposta = client.post("/auth/login", json={"email": "ana@escola.br", "senha": SENHAS["ana@escola.br"]})
    assert resposta.status_code == 429


def test_ct10_senha_gravada_com_bcrypt(client):
    """CT10 - A senha nunca pode ser gravada em texto puro ou com MD5/SHA sem salt."""
    senha = "SenhaDoTeste@123"
    resposta = client.post("/auth/registro", json={"nome": "Davi", "email": "davi@escola.br", "senha": senha})
    assert resposta.status_code == 201
    assert "senha" not in resposta.text.lower()

    gravada = usuario_por_email("davi@escola.br").senha_hash
    assert gravada != senha
    assert gravada != hashlib.md5(senha.encode()).hexdigest()  # nosec B324 - apenas comparacao no teste
    assert gravada != hashlib.sha256(senha.encode()).hexdigest()
    assert gravada.startswith(("$2a$", "$2b$", "$2y$")), "A senha deveria estar com hash bcrypt"
