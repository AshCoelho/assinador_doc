# models.py
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from sqlalchemy.dialects.postgresql import CITEXT  # requer extensão citext no Postgres

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = "users"

    id          = db.Column(db.Integer, primary_key=True)
    email       = db.Column(CITEXT, unique=True, nullable=False, index=True)
    nome        = db.Column(db.String(255), nullable=False)

    # CPF protegido
    cpf_hash    = db.Column(db.String(255), nullable=False)   # hash para autenticação
    cpf_masked  = db.Column(db.String(32),  nullable=False)   # exibido na UI (ex.: 123.***.***-**)

    # >>> NOVOS CAMPOS <<<
    orgao       = db.Column(db.String(120))
    setor       = db.Column(db.String(120))
    matricula   = db.Column(db.String(50))
    cargo       = db.Column(db.String(120))

    is_admin    = db.Column(db.Boolean, default=False, nullable=False)

    created_at  = db.Column(db.DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at  = db.Column(db.DateTime(timezone=True), server_default=func.now(),
                            onupdate=func.now(), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "nome": self.nome,
            "cpf_masked": self.cpf_masked,
            "orgao": self.orgao,
            "setor": self.setor,
            "matricula": self.matricula,
            "cargo": self.cargo,
            "is_admin": self.is_admin,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self):
        return f"<User {self.email}>"
