from app import app, db
from models import Usuario
import sqlite3

with app.app_context():
    # Conectar ao banco
    conn = sqlite3.connect('instance/feedbacks.db')
    cursor = conn.cursor()

    # Criar tabela temporária com novos campos
    cursor.execute("""
        CREATE TABLE usuario_temp (
            id INTEGER PRIMARY KEY,
            nome TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            senha_hash TEXT NOT NULL,
            cargo TEXT,
            setor_id INTEGER,
            is_admin BOOLEAN DEFAULT FALSE,
            reset_token TEXT,
            reset_token_expiry DATETIME,
            FOREIGN KEY (setor_id) REFERENCES setor(id)
        )
    """)

    # Copiar dados
    cursor.execute("""
        INSERT INTO usuario_temp (id, nome, email, senha_hash, cargo, setor_id, is_admin)
        SELECT id, nome, email, senha_hash, cargo, setor_id, is_admin FROM Usuario
    """)

    # Excluir tabela antiga
    cursor.execute("DROP TABLE Usuario")

    # Renomear tabela temporária
    cursor.execute("ALTER TABLE usuario_temp RENAME TO Usuario")

    # Commit e fechar
    conn.commit()
    conn.close()

    # Recriar índices e verificar
    db.create_all()