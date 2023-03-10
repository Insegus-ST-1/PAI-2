import socket
from Crypto.Cipher import AES
from Crypto.Random import random, get_random_bytes
from Crypto.Util.Padding import pad
import hashlib
import time

#Socket destino
HOST = '127.0.0.1'
PORT = 65432

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    #Recibe datos de la clave compartida entre cliente y servidor
    p_number_bytes = s.recv(128)
    p_number = int.from_bytes(p_number_bytes,byteorder='big')
    g_number_bytes = s.recv(128)
    g_number = int.from_bytes(g_number_bytes,byteorder='big')
    A_key_bytes = s.recv(128)
    A_key = int.from_bytes(A_key_bytes,byteorder='big')

    #Calcula clave publica para compartirla con el servidor
    b_secret = get_random_bytes(16)
    B_key = pow(g_number,int.from_bytes(b_secret,byteorder='big'),p_number)
    s.sendall(B_key.to_bytes(128,byteorder='big'))

    #Calcula clave compartida para enviar mensaje
    shared_key = pow(A_key,int.from_bytes(b_secret,byteorder='big'),p_number)
    


    #Cifrado del mensaje
    
    iv = get_random_bytes(16)
    s.sendall(iv)
    cipher = AES.new(shared_key.to_bytes(32, byteorder='big'), AES.MODE_CBC,iv)
    plain_mssg = 'Hola que tal'.encode('utf-8')
    padded_mssg = pad(plain_mssg, AES.block_size)
    #Calculo del hmac
    nonce = int(time.time()*1000)
    print(nonce)
    integrity_check = hashlib.sha256(plain_mssg)
    integrity_check.update(str(shared_key).encode('utf-8'))
    integrity_check.update(str(nonce).encode('utf-8'))
    cipher_mssg = cipher.encrypt(padded_mssg)
    print(f"Mensaje cifrado: {cipher_mssg.hex()}")
    s.sendall(cipher_mssg)
    nonce_bytes = nonce.to_bytes(32,'big')
    s.sendall(nonce_bytes)
    s.sendall(integrity_check.digest())
    
