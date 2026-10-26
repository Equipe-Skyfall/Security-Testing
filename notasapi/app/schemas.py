"""Esquemas de entrada e saida."""
from pydantic import BaseModel


class RegistroIn(BaseModel):
    nome: str
    email: str
    senha: str


class LoginIn(BaseModel):
    email: str
    senha: str


class NotaIn(BaseModel):
    aluno_id: int
    disciplina: str
    valor: float


class UsuarioOut(BaseModel):
    id: int
    nome: str
    email: str
    papel: str


class NotaOut(BaseModel):
    id: int
    aluno_id: int
    disciplina: str
    valor: float


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
