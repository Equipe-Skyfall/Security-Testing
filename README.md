# Testes Não Funcionais: Testes de Segurança (Security Testing)

Pesquisa semestral da disciplina de Qualidade e Testes de Software (6º semestre DSM — FATEC São
José dos Campos, Prof. Lucas Nadalete). Apresentação em 26/11/2026.

**Equipe:** Eduardo Fontes, Eduardo Kuwahara, Fábio Hiroshi, João Rossi, Kathellyn Caroline,
Paulo Henrique e Victor Daniel.

## Conteúdo do repositório

| Item | Descrição |
|---|---|
| [`notasapi/`](notasapi/) | Exemplo prático: API REST de notas com falhas de segurança propositais, testes de segurança e instruções de execução ([README](notasapi/README.md)) |
| [`.github/workflows/seguranca.yml`](.github/workflows/seguranca.yml) | Pipeline no GitHub Actions: SAST (Bandit, Semgrep), SCA (pip-audit), segredos (Gitleaks), testes de abuso (pytest) e DAST (OWASP ZAP) |
| [`Apresentacao_Security_Testing.pptx`](Apresentacao_Security_Testing.pptx) | Slides da apresentação, com notas do apresentador |
| [`Apresentacao_Security_Testing.pdf`](Apresentacao_Security_Testing.pdf) | Os mesmos slides em PDF |
| [`Roteiro_Pesquisa_Security_Testing.pdf`](Roteiro_Pesquisa_Security_Testing.pdf) | Roteiro da pesquisa entregue anteriormente |

## Branches

| Branch | Conteúdo | Pipeline |
|---|---|---|
| [`main`](https://github.com/Equipe-Skyfall/Security-Testing/tree/main) | NotasAPI corrigida | ✅ aprova |
| [`vulneravel`](https://github.com/Equipe-Skyfall/Security-Testing/tree/vulneravel) | NotasAPI com as falhas propositais | ❌ reprova |

Os resultados de cada execução da pipeline ficam na aba
[Actions](https://github.com/Equipe-Skyfall/Security-Testing/actions).
