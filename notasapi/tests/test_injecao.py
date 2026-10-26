"""OWASP A03:2021 - Injection."""
import pytest

from conftest import auth, login

PAYLOADS_SQL = [
    "' OR '1'='1",
    "x' UNION SELECT email, senha_hash FROM usuarios --",
    "%' OR papel='PROFESSOR' --",
]


@pytest.mark.parametrize("payload", PAYLOADS_SQL)
def test_ct08_injecao_de_sql_na_busca_de_alunos(client, payload):
    """CT08 - Injecao de SQL em GET /alunos?nome= nao pode retornar dados extras."""
    token_ana = login(client, "ana@escola.br")
    resposta = client.get("/alunos", params={"nome": payload}, headers=auth(token_ana))

    assert resposta.status_code == 200
    texto = resposta.text
    assert "Carla" not in texto, "A busca de alunos vazou o professor"
    assert "@escola.br" not in texto, "A busca de alunos vazou e-mails"
    assert resposta.json() == [], "Nenhum aluno tem esse texto no nome"


def test_ct08_busca_legitima_continua_funcionando(client):
    """CT08 (controle) - Buscar por parte do nome continua funcionando."""
    token_ana = login(client, "ana@escola.br")
    resposta = client.get("/alunos", params={"nome": "Bru"}, headers=auth(token_ana))
    assert resposta.status_code == 200
    assert [a["nome"] for a in resposta.json()] == ["Bruno Aluno"]
