
# -*- coding: UTF-8 -*-
from typing import cast
from tkinter.filedialog import askopenfilename, asksaveasfilename
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os
import tkinter as tk
from tkinter.filedialog import askopenfilename, asksaveasfilename
import operations
from tkinter import messagebox
import time
import base64
from tkinter import *



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
'''
def load_private_key(passcode):
    passcode = passcode.encode()
    #open private key with password
    with open("./private_key.pem", "rb") as key_file:
        private_key_from_file = serialization.load_pem_private_key(
            key_file.read(),
            password=passcode,
        )

        return private_key_from_file
'''


'''
def load_public_key():
    #open public key
    with open("./public_key.pem", "rb") as key_file:
        public_key_from_file = serialization.load_pem_public_key(
            key_file.read()
        )
    
    return public_key_from_file

'''

def save_file(ciphertext):
    """Save the current file as a new file."""
    filepath = asksaveasfilename(
        defaultextension="*.bin",
        filetypes=[("Binary", "*.bin"), ("All Files", "*.*")],
    )
    if not filepath:
        return
    
    with open(filepath, "wb") as output_file:
        output_file.write(ciphertext)

     




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


    save_file(ciphertext)

    #return ciphertext


def decrypt(ciphertext,private_key):
    
    plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
        )
    )
    #f = open("./saida.txt", "wb")
    #f.write(plaintext)
    #f.close()

    #print(plaintext)
    return plaintext
