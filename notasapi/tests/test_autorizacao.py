"""OWASP API1 (BOLA/IDOR), API3 (mass assignment) e API5 (BFLA) de 2023."""
from conftest import auth, login, usuario_por_email


def test_ct05_aluno_nao_pode_lancar_nota(client):
    """CT05 - Aluno tentando lancar nota (rota exclusiva de professor)."""
    token_ana = login(client, "ana@escola.br")
    ana = usuario_por_email("ana@escola.br")
    resposta = client.post("/notas", headers=auth(token_ana),
                           json={"aluno_id": ana.id, "disciplina": "Matematica", "valor": 10})
    assert resposta.status_code == 403


def test_ct05_professor_pode_lancar_nota(client):
    """CT05 (controle) - A regra de negocio continua funcionando para quem tem permissao."""
    token_carla = login(client, "carla@escola.br")
    ana = usuario_por_email("ana@escola.br")
    resposta = client.post("/notas", headers=auth(token_carla),
                           json={"aluno_id": ana.id, "disciplina": "Quimica", "valor": 9})
    assert resposta.status_code == 201


def test_ct06_aluno_nao_le_nota_de_outro_aluno(client):
    """CT06 - Aluna Ana trocando o id na URL para ler a nota do Bruno (IDOR/BOLA)."""
    token_ana = login(client, "ana@escola.br")
    token_bruno = login(client, "bruno@escola.br")
    nota_do_bruno = client.get("/notas/minhas", headers=auth(token_bruno)).json()[0]

    resposta = client.get(f"/notas/{nota_do_bruno['id']}", headers=auth(token_ana))
    assert resposta.status_code in (403, 404)
    assert nota_do_bruno["disciplina"] not in resposta.text


def test_ct06_aluno_le_a_propria_nota(client):
    """CT06 (controle) - O dono da nota continua tendo acesso a ela."""
    token_ana = login(client, "ana@escola.br")
    nota_da_ana = client.get("/notas/minhas", headers=auth(token_ana)).json()[0]
    resposta = client.get(f"/notas/{nota_da_ana['id']}", headers=auth(token_ana))
    assert resposta.status_code == 200


def test_ct07_aluno_nao_se_promove_a_professor(client):
    """CT07 - Envio de "papel": "PROFESSOR" em PATCH /usuarios/me (mass assignment)."""
    token_ana = login(client, "ana@escola.br")
    resposta = client.patch("/usuarios/me", headers=auth(token_ana),
                            json={"nome": "Ana Aluna", "papel": "PROFESSOR"})
    assert resposta.status_code in (200, 422)
    assert usuario_por_email("ana@escola.br").papel == "ALUNO"


def test_ct07_atualizacao_legitima_continua_funcionando(client):
    """CT07 (controle) - Alterar apenas o nome continua permitido."""
    token_ana = login(client, "ana@escola.br")
    resposta = client.patch("/usuarios/me", headers=auth(token_ana), json={"nome": "Ana Souza"})
    assert resposta.status_code == 200
    assert usuario_por_email("ana@escola.br").nome == "Ana Souza"
