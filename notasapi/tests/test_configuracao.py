"""OWASP A05:2021 - Security Misconfiguration."""
from conftest import auth, login

ORIGEM_MALICIOSA = "http://site-malicioso.com"


def test_ct11_cors_nao_libera_origem_desconhecida(client):
    """CT11 - Requisicao de origem nao autorizada nao recebe Access-Control-Allow-Origin."""
    preflight = client.options("/notas/minhas", headers={
        "Origin": ORIGEM_MALICIOSA,
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "Authorization",
    })
    assert "access-control-allow-origin" not in preflight.headers

    simples = client.post("/auth/login", headers={"Origin": ORIGEM_MALICIOSA},
                          json={"email": "ana@escola.br", "senha": "x"})
    assert "access-control-allow-origin" not in simples.headers


def test_ct15_cabecalhos_de_seguranca_presentes(client):
    """CT15 (complemento ao ZAP) - Cabecalhos de seguranca em todas as respostas da API."""
    resposta = client.post("/auth/login", json={"email": "ninguem@escola.br", "senha": "x"})
    cabecalhos = resposta.headers
    assert cabecalhos.get("x-content-type-options") == "nosniff"
    assert cabecalhos.get("x-frame-options") == "DENY"
    assert "default-src 'none'" in cabecalhos.get("content-security-policy", "")
    assert cabecalhos.get("cache-control") == "no-store"


def test_ct16_email_duplicado_nao_gera_erro_500(client):
    """CT16 (encontrado pelo OWASP ZAP) - Trocar o e-mail para um ja usado nao pode derrubar a rota.

    O ZAP enviou e-mails repetidos ao PATCH /usuarios/me e recebeu HTTP 500
    (excecao de UNIQUE nao tratada). O achado virou este teste de regressao.
    """
    token_ana = login(client, "ana@escola.br")
    resposta = client.patch("/usuarios/me", headers=auth(token_ana), json={"email": "bruno@escola.br"})
    assert resposta.status_code == 409
    assert "IntegrityError" not in resposta.text
