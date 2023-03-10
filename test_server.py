import socket
from Crypto.Cipher import AES
from Crypto.Random import random, get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import threading
import settings
import serverdb

#Cambiar para permitir comunicacion entre diferentes ordenadores
HOST = '127.0.0.1'
#Asignar puerto disponible
PORT = 65432
lock = threading.Lock()
#Implementacion de Diffie-Hellman para asegurar el intercambio de clave entre cliente y servidor al conectarse por primera vez
#Datos sacados de la implementacion de Elgamal del otro proyecto
p_number = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
g_number = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
a_secret = get_random_bytes(16)
A_key = pow(g_number, int.from_bytes(a_secret,byteorder='big'),p_number)

def decrypt_mssg(data, cipher):
    print(data.hex())
    decripted_mssg = unpad(cipher.decrypt(data), AES.block_size).decode('utf-8')
    return decripted_mssg


def check_integrity(client_hash, message, nonce):
    global shared_key
    hash = hashlib.sha256(message.encode('utf-8'))
    hash.update(str(shared_key).encode('utf-8'))
    hash.update(str(nonce).encode('utf-8'))
    print(nonce)
    return client_hash.hex() == hash.hexdigest()

def log_mssg(client,message,code,file):
    global lock
    lock.acquire()
    text = f'Client {client} has made a transaction:\n{message}\nOperation Code: {code}\n==============================================\n'
    with open(file, 'a') as f:
        f.write(text)
    lock.release()

def log_daily_res(log_data, file):
    global lock
    lock.acquire()
    text = f'Resultados del dia {log_data[0]}:\nMensajes recibidos: {log_data[1]}\tMensajes comprometidos: {log_data[2]} ({round(log_data[2]/log_data[1]*100, 2)}%)\tMensajes replicados: {log_data[3]} ({round(log_data[3]/log_data[1]*100,2)}%)'
    with open(file, 'a') as f:
        f.write(text)
    lock.release()

def log_mensual(data, file):
    global lock
    lock.acquire()
    text = f'Resultados mensuales:\nSe han realizado un total de {data[0]} transaccciones, de las cuales, se han producido {data[1]+data[2]} ({round((data[1]+data[2])/data[0]*100,2)} %) errores\nErrores de integridad: {data[1]} ({round(data[1]/data[0]*100,2)} %)\tErrores de replicacion: {data[2]} ({round(data[2]/data[0]*100,2)})'
    with open(file, 'w') as f:
        f.write(text)
    lock.release()

def create_log_file(file):
    f = open(file,'w')
    f.close()

def rcv_mssg():
    global conn,addr, cipher, shared_key, file, error, replica
    data = conn.recv(1024)
    message = decrypt_mssg(data=data, cipher=cipher)
    print(message)

    #Verificacion de la integridad
    code = 'VERIFICATION_OK'
    nonce_bytes = conn.recv(32)
    nonce = int.from_bytes(nonce_bytes, byteorder='big')
    integrity_check = conn.recv(1024)
    mssg_ok = check_integrity(client_hash=integrity_check,message=message, nonce=nonce)
    db_nonce_exists = serverdb.check_nonce_exists(str(nonce).encode('utf-8'))
    if db_nonce_exists:
        code = 'REPLICATION_ERR'
        replica += 1
    elif not db_nonce_exists:
        serverdb.insert_nonce(str(nonce).encode('utf-8'))
    if not mssg_ok:
        code = 'INTEGRITY_ERR'
        error += 1
    log_mssg(code=code,client=addr,message=message,file=file)



with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
    s.bind((HOST,PORT))
    s.listen()
    print("Servidor activo")
    conn, addr = s.accept()
    with conn:
        print(f"Conexión establecida con {addr}")
        #Envia a cliente datos suficientes para generar la clave compartida entre ambos
        conn.sendall(p_number.to_bytes(128, byteorder='big'))
        conn.sendall(g_number.to_bytes(128,byteorder='big'))
        conn.sendall(A_key.to_bytes(128, byteorder='big'))

        #Cliente manda su clave publica para realizar la clave compartida con servidor
        B_key_bytes = conn.recv(128)
        B_key = int.from_bytes(B_key_bytes,byteorder='big')

        shared_key = pow(B_key,int.from_bytes(a_secret,byteorder='big'),p_number)
        iv = conn.recv(AES.block_size)
        print(iv)
        #Metodo de cifrado usado
        cipher = AES.new(shared_key.to_bytes(32, byteorder='big'), AES.MODE_CBC, iv)

        
        #Cliente envia mensaje cifrado a servidor
        serverdb.create_db()
        for i in range(1,settings.DAYS+1):
            file = f'files/log_{i}.txt'
            create_log_file(file)
            daymssgs = int.from_bytes(conn.recv(32), byteorder='big')
            error, replica = 0, 0
            for i in range(1,daymssgs+1):
                rcv_mssg()
            log_data = (i,daymssgs,error,replica)
            log_daily_res(log_data=log_data,file=file)
            serverdb.daily_log_res(log_data)
        mensual_log = 'files/mensual_report.txt'
        mensual_data = serverdb.mensual_report()
        log_mensual(data=mensual_data,file=mensual_log)
        serverdb.close_db()
        
        

        




