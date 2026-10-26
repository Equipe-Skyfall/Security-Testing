"""Dados ficticios usados na demonstracao e nos testes."""
from sqlalchemy.orm import Session

from app.models import ALUNO, PROFESSOR, Nota, Usuario
from app.security import gerar_hash_senha

USUARIOS_DEMO = [
    # (nome, email, senha, papel)
    ("Carla Professora", "carla@escola.br", "Professora@2026", PROFESSOR),
    ("Ana Aluna", "ana@escola.br", "AnaAluna@2026", ALUNO),
    ("Bruno Aluno", "bruno@escola.br", "BrunoAluno@2026", ALUNO),
]


def popular_banco(db: Session) -> None:
    if db.query(Usuario).count() > 0:
        return
    usuarios = {}
    for nome, email, senha, papel in USUARIOS_DEMO:
        usuario = Usuario(nome=nome, email=email, senha_hash=gerar_hash_senha(senha), papel=papel)
        db.add(usuario)
        usuarios[email] = usuario
    db.flush()
    professora = usuarios["carla@escola.br"]
    db.add_all([
        Nota(aluno_id=usuarios["ana@escola.br"].id, disciplina="Matematica", valor=8.5, lancada_por=professora.id),
        Nota(aluno_id=usuarios["bruno@escola.br"].id, disciplina="Matematica", valor=4.0, lancada_por=professora.id),
        Nota(aluno_id=usuarios["bruno@escola.br"].id, disciplina="Fisica", valor=6.0, lancada_por=professora.id),
    ])
    db.commit()
