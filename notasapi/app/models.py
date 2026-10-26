from sqlalchemy import Float, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base

ALUNO = "ALUNO"
PROFESSOR = "PROFESSOR"


class Usuario(Base):
    __tablename__ = "usuarios"

    id: Mapped[int] = mapped_column(primary_key=True)
    nome: Mapped[str] = mapped_column(String(100))
    email: Mapped[str] = mapped_column(String(120), unique=True)
    senha_hash: Mapped[str] = mapped_column(String(100))
    papel: Mapped[str] = mapped_column(String(20), default=ALUNO)


class Nota(Base):
    __tablename__ = "notas"

    id: Mapped[int] = mapped_column(primary_key=True)
    aluno_id: Mapped[int] = mapped_column(ForeignKey("usuarios.id"))
    disciplina: Mapped[str] = mapped_column(String(80))
    valor: Mapped[float] = mapped_column(Float)
    lancada_por: Mapped[int] = mapped_column(ForeignKey("usuarios.id"))
