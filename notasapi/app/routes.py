"""Rotas da NotasAPI.

ATENCAO: versao VULNERAVEL de proposito (branch vulneravel). Nao use em producao.
"""
from fastapi import APIRouter, Body, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import ALUNO, Nota, Usuario
from app.schemas import LoginIn, NotaIn, NotaOut, RegistroIn, TokenOut, UsuarioOut
from app.security import criar_token, gerar_hash_senha, usuario_atual, verificar_senha

router = APIRouter()


@router.post("/auth/registro", response_model=UsuarioOut, status_code=status.HTTP_201_CREATED, tags=["auth"])
def registrar(dados: RegistroIn, db: Session = Depends(get_db)):
    if db.query(Usuario).filter(Usuario.email == dados.email).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="E-mail ja cadastrado")
    usuario = Usuario(nome=dados.nome, email=dados.email, senha_hash=gerar_hash_senha(dados.senha), papel=ALUNO)
    db.add(usuario)
    db.commit()
    db.refresh(usuario)
    return usuario


@router.post("/auth/login", response_model=TokenOut, tags=["auth"])
def login(dados: LoginIn, db: Session = Depends(get_db)):
    # FALHA: sem limite de tentativas - permite forca bruta na senha.
    usuario = db.query(Usuario).filter(Usuario.email == dados.email).first()
    if usuario is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="E-mail nao cadastrado")
    if not verificar_senha(dados.senha, usuario.senha_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Senha incorreta")
    return TokenOut(access_token=criar_token(usuario))


@router.get("/notas/minhas", response_model=list[NotaOut], tags=["notas"])
def minhas_notas(usuario: Usuario = Depends(usuario_atual), db: Session = Depends(get_db)):
    return db.query(Nota).filter(Nota.aluno_id == usuario.id).all()


@router.get("/notas/{nota_id}", response_model=NotaOut, tags=["notas"])
def detalhar_nota(nota_id: int, usuario: Usuario = Depends(usuario_atual), db: Session = Depends(get_db)):
    # FALHA (IDOR/BOLA): nao verifica se a nota pertence ao usuario autenticado.
    nota = db.get(Nota, nota_id)
    if nota is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Nota nao encontrada")
    return nota


@router.post("/notas", response_model=NotaOut, status_code=status.HTTP_201_CREATED, tags=["notas"])
def lancar_nota(dados: NotaIn, usuario: Usuario = Depends(usuario_atual), db: Session = Depends(get_db)):
    # FALHA (autorizacao por funcao): nao verifica se o usuario e PROFESSOR.
    nota = Nota(aluno_id=dados.aluno_id, disciplina=dados.disciplina, valor=dados.valor, lancada_por=usuario.id)
    db.add(nota)
    db.commit()
    db.refresh(nota)
    return nota


@router.get("/alunos", tags=["alunos"])
def buscar_alunos(nome: str = "", _usuario: Usuario = Depends(usuario_atual), db: Session = Depends(get_db)):
    # FALHA (injecao de SQL): o texto digitado e concatenado direto na consulta.
    sql = f"SELECT id, nome FROM usuarios WHERE papel = 'ALUNO' AND nome LIKE '%{nome}%'"
    linhas = db.execute(text(sql)).all()
    return [{"id": linha[0], "nome": linha[1]} for linha in linhas]


@router.patch("/usuarios/me", response_model=UsuarioOut, tags=["usuarios"])
def atualizar_me(dados: dict = Body(...), usuario: Usuario = Depends(usuario_atual), db: Session = Depends(get_db)):
    # FALHA (mass assignment): copia QUALQUER campo enviado, inclusive "papel".
    usuario = db.get(Usuario, usuario.id)
    for campo, valor in dados.items():
        setattr(usuario, campo, valor)
    db.commit()
    db.refresh(usuario)
    return usuario
