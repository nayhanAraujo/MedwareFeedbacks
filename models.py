from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import check_password_hash

db = SQLAlchemy()



class ConfiguracaoAvaliacao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'))
    notas = db.Column(db.String(100))  # ex: "1,2,3,4,5" ou "2.5,3.75,5"



class NotaPermitida(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    valor = db.Column(db.Numeric(4, 2), nullable=False)
    setor_id = db.Column(db.Integer, db.ForeignKey('setor.id'), nullable=False)

    __table_args__ = (
        db.UniqueConstraint('valor', 'setor_id', name='valor_por_setor_unique'),
    )

    setor = db.relationship('Setor', backref='notas_permitidas')


# MODELOS
class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    senha_hash = db.Column(db.String(128), nullable=False)
    cargo = db.Column(db.String(100))
    setor_id = db.Column(db.Integer, db.ForeignKey('setor.id'))
    is_admin = db.Column(db.Boolean, default=False)
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expiry = db.Column(db.DateTime, nullable=True)

    setor = db.relationship('Setor', backref=db.backref('usuarios', lazy=True))

    def verificar_senha(self, senha):
        return check_password_hash(self.senha_hash, senha)

# ... (outros modelos como Feedback, NotaPermitida, etc. mantidos inalterados)

class CategoriaHabilidade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    setor_id = db.Column(db.Integer, db.ForeignKey('setor.id'))
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'))  # opcional
    ativa = db.Column(db.Boolean, default=True)

    setor = db.relationship('Setor')
    usuario = db.relationship('Usuario')


class Habilidades(db.Model):
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    nome = db.Column(db.String(100), nullable=False)
    categoria_id = db.Column(db.Integer, db.ForeignKey('categoria_habilidade.id'))
    ativa = db.Column(db.Boolean, default=True)

    categoria = db.relationship('CategoriaHabilidade')


class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_usuario = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=True)
    texto = db.Column(db.Text, nullable=False)
    categoria = db.Column(db.String(50))
    anonimo = db.Column(db.Boolean, default=False)
    data_envio = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='novo')

class Resposta(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_feedback = db.Column(db.Integer, db.ForeignKey('feedback.id'))
    id_usuario = db.Column(db.Integer, db.ForeignKey('usuario.id'))
    resposta = db.Column(db.Text, nullable=False)
    data_resposta = db.Column(db.DateTime, default=datetime.utcnow)

class AcaoCorretiva(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_avaliacao = db.Column(db.Integer, db.ForeignKey('avaliacao.id'), nullable=False) # Adicione nullable=False se uma ação corretiva DEVE ter uma avaliação
    descricao = db.Column(db.String(255))
    responsavel = db.Column(db.String(100))
    prazo = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='pendente')
    data_criacao = db.Column(db.DateTime, default=datetime.utcnow) # Esta linha


class Avaliacao(db.Model):
    __tablename__ = 'avaliacao'
    id = db.Column(db.Integer, primary_key=True)
    id_funcionario = db.Column(db.Integer, db.ForeignKey('usuario.id'))
    id_avaliador = db.Column(db.Integer, db.ForeignKey('usuario.id'))
    data_avaliacao = db.Column(db.DateTime, default=datetime.utcnow)
    observacoes = db.Column(db.Text)
    sentimento = db.Column(db.Text)  # Nova coluna para sentimento
    itens = db.relationship('AvaliacaoItem', backref='avaliacao', cascade='all, delete-orphan')
    funcionario = db.relationship('Usuario', foreign_keys=[id_funcionario])
    avaliador = db.relationship('Usuario', foreign_keys=[id_avaliador])
    resumos = db.relationship('AvaliacaoResumo', backref='avaliacao', cascade='all, delete-orphan')
    acoes_corretivas = db.relationship('AcaoCorretiva', backref='avaliacao', cascade='all, delete-orphan')



class AvaliacaoResumo(db.Model):
    __tablename__ = 'avaliacao_resumo'
    id = db.Column(db.Integer, primary_key=True)
    id_avaliacao = db.Column(db.Integer, db.ForeignKey('avaliacao.id'), nullable=False)
    resumo = db.Column(db.Text, nullable=False)
    data_criacao = db.Column(db.DateTime, default=db.func.current_timestamp())

class AvaliacaoItem(db.Model):
    __tablename__ = 'avaliacao_item'  # Força o nome da tabela

    id = db.Column(db.Integer, primary_key=True)
    id_avaliacao = db.Column(db.Integer, db.ForeignKey('avaliacao.id'))
    nome_habilidade = db.Column(db.String(100))
    categoria = db.Column(db.String(50))
    nota = db.Column(db.Float)
    comentario = db.Column(db.Text, nullable=True) # Use Text para comentários mais longos, nullable=True para permitir comentários vazios




class Habilidade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    categoria = db.Column(db.String(50))  # 'Geral' ou 'Tecnica'
    ativa = db.Column(db.Boolean, default=True)




 #MODELO SETOR
class Setor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False, unique=True)


