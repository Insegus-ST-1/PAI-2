import socket
from Crypto.Cipher import AES
from Crypto.Random import random, get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import struct
#Cambiar para permitir comunicacion entre diferentes ordenadores
HOST = '127.0.0.1'
#Asignar puerto disponible
PORT = 65432

#Implementacion de Diffie-Hellman para asegurar el intercambio de clave entre cliente y servidor al conectarse por primera vez
#Datos sacados de la implementacion de Elgamal del otro proyecto
p_number = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
g_number = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
a_secret = get_random_bytes(16)
A_key = pow(g_number, int.from_bytes(a_secret,byteorder='big'),p_number)

def decrypt_mssg(data, cipher):
    decripted_mssg = unpad(cipher.decrypt(data), AES.block_size).decode('utf-8')
    return decripted_mssg


def check_integrity(client_hash, message, nonce):
    global shared_key
    hash = hashlib.sha256(message.encode('utf-8'))
    hash.update(str(shared_key).encode('utf-8'))
    hash.update(str(nonce).encode('utf-8'))
    print(nonce)
    return client_hash.hex() == hash.hexdigest()

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

        #Metodo de cifrado usado
        cipher = AES.new(shared_key.to_bytes(32, byteorder='big'), AES.MODE_CBC, iv)

        #Cliente envia mensaje cifrado a servidor
        data = conn.recv(1024)
        message = decrypt_mssg(data=data, cipher=cipher)

        #Verificacion de la integridad
        nonce_bytes = conn.recv(32)
        nonce = int.from_bytes(nonce_bytes, byteorder='big')
        integrity_check = conn.recv(1024)
        

        print(check_integrity(client_hash=integrity_check,message=message, nonce=nonce))




