import socket
from Crypto.Cipher import AES
from Crypto.Random import random, get_random_bytes
from Crypto.Util.Padding import pad
import hashlib
import time
import settings

#Socket destino
HOST = '127.0.0.1'
PORT = 65432

def send_mssg():
    global s
    global cipher
    global previous_mssg
    transaction = random.randint(100,20000)
    plain_mssg = f'From: ISBN123456789\tTo:ISBN987654321\tTransfer: {transaction} euros'.encode('utf-8')
    
    #Calculo del hmac
    nonce = int(time.time()*1000)
    integrity_check = hashlib.sha256(plain_mssg)
    integrity_check.update(str(shared_key).encode('utf-8'))
    integrity_check.update(str(nonce).encode('utf-8'))
    
    #Si no hay mensaje previo, lo carga
    if previous_mssg[0] is None:
        previous_mssg = (plain_mssg, nonce, integrity_check)
    
    #Simulacion de ataque
    is_attack = random.randint(0,settings.MAX_RNG_VALUE)
    #Ataque de integridad
    if is_attack > settings.UMBRAL_OK_MSSG and is_attack <= settings.UMBRAL_INTEGRITY_ERR:
        plain_mssg = f'From: ISBN123456789\tTo:ISBN987654321\tTransfer: {transaction*100} euros'.encode('utf-8')
    #Ataque de replicacion
    elif is_attack > settings.UMBRAL_INTEGRITY_ERR:
        plain_mssg, nonce, integrity_check = previous_mssg

    #Cifrado de mensaje
    cipher_mssg = cipher.encrypt(pad(plain_mssg, AES.block_size))
    print(cipher_mssg.hex())
    s.sendall(cipher_mssg)
    nonce_bytes = nonce.to_bytes(32,'big')
    time.sleep(1)
    s.sendall(nonce_bytes)
    time.sleep(1)
    s.sendall(integrity_check.digest())
    previous_mssg = (plain_mssg, nonce, integrity_check)


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

    #Cantidad de mensajes
    previous_mssg = (None,None,None)
    
    for i in range(1,settings.DAYS+1):
        daymssgs:int = random.randint(settings.MIN_MSSGS_PER_DAY,settings.MAX_MSSGS_PER_DAY)
        s.sendall(daymssgs.to_bytes(32,byteorder='big'))
        for i in range(1,daymssgs+1):
            send_mssg()
            time.sleep(1)
    
    
    
