from typing import cast
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os

#gera a chave privada e publica e armazena em arquivos
def key_pair(passcode):
    passcode = passcode.encode()
    private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048,)
    public_key = private_key.public_key()

    #para armazenar a chave privada no arquivo
    pem_private_key = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(passcode)
    )
    f = open("./private_key.pem", "wb")
    f.write(pem_private_key)
    f.close()


    #para armazenar a chave publica no arquivo
    pem_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    f = open("./public_key.pem", "wb")
    f.write(pem_public_key)
    f.close()

    #return private_key,public_key

def load_key_pair(passcode):
    passcode = passcode.encode()
    #open private key with password
    with open("./private_key.pem", "rb") as key_file:
        private_key_from_file = serialization.load_pem_private_key(
            key_file.read(),
            password=passcode,
        )

    #open public key
    with open("./public_key.pem", "rb") as key_file:
        public_key_from_file = serialization.load_pem_public_key(
            key_file.read()
        )
    
    return private_key_from_file,public_key_from_file



def encrypt(message,public_key):
    message = message.encode()
    ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
                 )
    )

    f = open("./encrypted-data", "wb")
    f.write(ciphertext)
    f.close()

    return ciphertext


def decrypt(ciphertext,private_key):
    
    plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
        )
    )
    f = open("./saida.txt", "wb")
    f.write(plaintext)
    f.close()


    return plaintext




while True:
    op = input('''1 - Encrypt\n2 - Decrypt\n3 - Create Key Pair\n4 - Load Key Pair\n> ''')


    if(op=='1'):


        f = open("./entrada.txt", "r")
        lines = f.read()
        encrypt(lines,public_key_from_file)
        print("Success to Encrypt")
    
        #print("Fail to Encrypt")


    if(op=='2'):
   
        f = open("./encrypted-data", "rb")
        lines = f.read()
        decrypt(lines,private_key_from_file)
    
        #print("Fail to decrypt")

    if(op=='3'):
        print("\ncreating a key pair...")
        passcode = input("enter the passcode to save (keep it safe): ")
        key_pair(passcode)
        print("Sucess!!!")
        #print("Fail to create a key pair")

    if(op=='4'):
        print("\nloading a key pair...")
        passcode = input("enter the passcode: ")
        private_key_from_file,public_key_from_file = load_key_pair(passcode)
        print(private_key_from_file)
        print(public_key_from_file)
        print("Sucess!!!")
        #print("Fail in loading.\nCheck the keys files in current directory")

