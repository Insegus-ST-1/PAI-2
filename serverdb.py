import sqlite3

def create_db():
    conn = sqlite3.connect('nonces.db')
    cr = conn.cursor()

    cr.execute("""CREATE TABLE IF NOT EXISTS nonces
    (nonce TEXT PRIMARY KEY)
    """)
    conn.commit()
    conn.close()

def insert_nonce(nonce:str):
    conn = sqlite3.connect('nonces.db')
    cr = conn.cursor()
    cr.execute("""INSERT INTO nonces (nonce)
    VALUES (?)
    """, (nonce,))
    conn.commit()
    conn.close()

def check_nonce_exists(nonce:str):
    conn = sqlite3.connect('nonces.db')
    cr = conn.cursor()
    cr.execute("""SELECT * FROM nonces WHERE nonce=?
    """, (nonce,))
    val = cr.fetchone()
    conn.close()
    return val is not None