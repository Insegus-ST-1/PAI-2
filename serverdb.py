import sqlite3

def create_db():
    conn = sqlite3.connect('nonces.db')
    cr = conn.cursor()

    cr.execute("""CREATE TABLE IF NOT EXISTS nonces
    (nonce TEXT PRIMARY KEY)
    """)
    conn.commit()

    cr.execute("""CREATE TABLE IF NOT EXISTS logs
    (id INTEGER PRIMARY KEY AUTOINCREMENT,
    total_mssgs INTEGER,
    integrity_err INTEGER,
    replication_err INTEGER)""")
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

def daily_log_res(log_data:tuple):
    conn = sqlite3.connect('nonces.db')
    cr = conn.cursor()
    cr.execute("""INSERT INTO logs (total_mssgs,integrity_err,replication_err)
    VALUES (?,?,?)
    """,(log_data[1],log_data[2],log_data[3]))
    conn.commit()
    conn.close()

def mensual_report():
    conn = sqlite3.connect('nonces.db')
    cr = conn.cursor()
    cr.execute("""SELECT * FROM logs
    """)
    logs = cr.fetchall()
    conn.close()
    total_mssgs_month = sum(log[1] for log in logs)
    total_integrity_err = sum(log[2] for log in logs)
    total_replication_err = sum(log[3] for log in logs)
    return total_mssgs_month,total_integrity_err,total_replication_err

def close_db():
    conn = sqlite3.connect('nonces.db')
    cr = conn.cursor()
    cr.execute("""DROP TABLE IF EXISTS logs
    """)
    conn.commit()
    conn.close()
