import sqlite3

conn = sqlite3.connect("instance/feedbacks.db")

with open("dados_exportados.sql", "w", encoding="utf-8") as f:
    for line in conn.iterdump():
        # Exporta apenas os INSERTs (evita recriar tabelas)
        if line.startswith("INSERT INTO"):
            f.write(f"{line}\n")

conn.close()
