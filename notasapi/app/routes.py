from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import ALUNO, PROFESSOR, Nota, Usuario
from app.schemas import (
    AlunoOut, LoginIn, NotaIn, NotaOut, RegistroIn, TokenOut, UsuarioOut, UsuarioUpdate,
)
from app.security import (
    criar_token, exigir_papel, gerar_hash_senha, limitador_login, usuario_atual, verificar_senha,
)

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
def login(dados: LoginIn, request: Request, db: Session = Depends(get_db)):
    chave = dados.email.lower()
    if limitador_login.bloqueado(chave):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Muitas tentativas. Tente mais tarde.")
    usuario = db.query(Usuario).filter(Usuario.email == dados.email).first()
    if usuario is None or not verificar_senha(dados.senha, usuario.senha_hash):
        limitador_login.registrar_falha(chave)
        # Mesma mensagem para e-mail inexistente e senha errada (nao revela quem esta cadastrado).
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciais invalidas")
    limitador_login.limpar(chave)
    return TokenOut(access_token=criar_token(usuario))


@router.get("/notas/minhas", response_model=list[NotaOut], tags=["notas"])
def minhas_notas(usuario: Usuario = Depends(exigir_papel(ALUNO)), db: Session = Depends(get_db)):
    return db.query(Nota).filter(Nota.aluno_id == usuario.id).all()


@router.get("/notas/{nota_id}", response_model=NotaOut, tags=["notas"])
def detalhar_nota(nota_id: int, usuario: Usuario = Depends(usuario_atual), db: Session = Depends(get_db)):
    nota = db.get(Nota, nota_id)
    # Autorizacao a nivel de objeto: so o dono da nota ou um professor podem ve-la.
    # Responde 404 (e nao 403) para nao revelar que a nota existe.
    if nota is None or (usuario.papel != PROFESSOR and nota.aluno_id != usuario.id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Nota nao encontrada")
    return nota


@router.post("/notas", response_model=NotaOut, status_code=status.HTTP_201_CREATED, tags=["notas"])
def lancar_nota(dados: NotaIn, professor: Usuario = Depends(exigir_papel(PROFESSOR)), db: Session = Depends(get_db)):
    aluno = db.get(Usuario, dados.aluno_id)
    if aluno is None or aluno.papel != ALUNO:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Aluno nao encontrado")
    nota = Nota(aluno_id=aluno.id, disciplina=dados.disciplina, valor=dados.valor, lancada_por=professor.id)
    db.add(nota)
    db.commit()
    db.refresh(nota)
    return nota


@router.get("/alunos", response_model=list[AlunoOut], tags=["alunos"])
def buscar_alunos(
    nome: str = Query(default="", max_length=100),
    _usuario: Usuario = Depends(usuario_atual),
    db: Session = Depends(get_db),
):
    # Consulta parametrizada pelo ORM: o texto digitado nunca vira parte do SQL.
    return db.query(Usuario).filter(Usuario.papel == ALUNO, Usuario.nome.ilike(f"%{nome}%")).all()


@router.patch("/usuarios/me", response_model=UsuarioOut, tags=["usuarios"])
def atualizar_me(dados: UsuarioUpdate, usuario: Usuario = Depends(usuario_atual), db: Session = Depends(get_db)):
    if dados.email is not None and dados.email != usuario.email and \
            db.query(Usuario).filter(Usuario.email == dados.email).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="E-mail ja cadastrado")
    # Somente os campos declarados em UsuarioUpdate (nome, email) podem ser alterados.
    for campo, valor in dados.model_dump(exclude_unset=True).items():
        setattr(usuario, campo, valor)
    db.commit()
    db.refresh(usuario)
    return usuario
