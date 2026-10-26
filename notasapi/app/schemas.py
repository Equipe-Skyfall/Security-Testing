"""Esquemas de entrada e saida.

extra="forbid" faz a API recusar (HTTP 422) qualquer campo que nao esteja
declarado aqui, o que impede mass assignment (ex.: enviar "papel").
"""
from pydantic import BaseModel, ConfigDict, Field


class Entrada(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RegistroIn(Entrada):
    nome: str = Field(min_length=2, max_length=100)
    email: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$", max_length=120)
    senha: str = Field(min_length=8, max_length=72)


class LoginIn(Entrada):
    email: str = Field(max_length=120)
    senha: str = Field(max_length=72)


class UsuarioUpdate(Entrada):
    nome: str | None = Field(default=None, min_length=2, max_length=100)
    email: str | None = Field(default=None, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$", max_length=120)


class NotaIn(Entrada):
    aluno_id: int
    disciplina: str = Field(min_length=2, max_length=80)
    valor: float = Field(ge=0, le=10)


class UsuarioOut(BaseModel):
    id: int
    nome: str
    email: str
    papel: str


class AlunoOut(BaseModel):
    id: int
    nome: str


class NotaOut(BaseModel):
    id: int
    aluno_id: int
    disciplina: str
    valor: float


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
