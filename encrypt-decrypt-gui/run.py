# -*- coding: UTF-8 -*-

from typing import cast
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
from tkinter import *
from tkinter import simpledialog

def create_key_pair(passcode="vincere"):
    try:
        messagebox.showwarning("Chaves", "Mantenha a chave privada em segurança e não compartilhe com ninguem !")
        passcode = simpledialog.askstring("Input", "Informe uma senha para a chave privada",
                                    parent=window)

        #gera a chave privada e publica e armazena em arquivos
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
        #lbl_keys_loaded.after(1000, lbl_keys_loaded.destroy)
        keys_loaded = check_keys()
        lbl_keys_loaded = tk.Label(fr_buttons,bg="green", text="", textvariable=keys_loaded[0])
        lbl_keys_loaded.grid(row=7, column=0, sticky="ew", padx=5)

        messagebox.showinfo("Chaves", "Par de chaves criado com sucesso ! Salve o em um local seguro !")
        
    except Exception as e:
        messagebox.showerror("Chaves", e)
        messagebox.showerror("Chaves", "Erro ao criar o par de chaves !")



def open_file():
    """Open a file for editing."""
    filepath = askopenfilename(
        filetypes=[("Binary", "*.bin"), ("All Files", "*.*")]
    )
    if not filepath:
        return
    txt_edit.delete(1.0, tk.END)

    with open(filepath, "rb") as input_file:
        cipher_text = input_file.read()

    return cipher_text


def encrypt_step_1():
    try:
        public_key = operations.load_public_key()

        #print(public_key)
        text = txt_edit.get(1.0, tk.END)
        #print(text)
        
        operations.encrypt(text,public_key)
        #print(cypher_text)
        messagebox.showinfo("Criptografia", "Dados criptografados com sucesso!")
        #txt_edit.delete(1.0, tk.END)
        #txt_edit.insert(tk.END, cypher_text)

    except Exception as e:
        print(e)
        messagebox.showerror("Criptografia", "Erro ao criar o arquivo criptografado!")

    

def decrypt_step_1():
    passcode = simpledialog.askstring("Input", "Informe a senha da chave privada",
                                parent=window)
    try:
    
        private_key = operations.load_private_key(passcode)


        cypher_text = open_file()
    
        plain_text = operations.decrypt(cypher_text,private_key)
        #decodifica para mostrar no campo de texto
        plain_text = plain_text.decode()
        txt_edit.delete(1.0, tk.END)
        txt_edit.insert(tk.END, plain_text)
        
    except Exception as e:
        print(e)
        messagebox.showerror("Descriptografar", "Senha inválida !")

  


def check_keys():
    keys_loaded = StringVar()
    try:
        sk = open("./private_key.pem")
        pk = open("./public_key.pem")
        messagebox.showinfo("Chaves", "Chaves carregadas com sucesso!")
        msg = "Chaves Carregadas"
        keys_loaded.set('Chaves Carregadas')
        return keys_loaded,msg

    # Do something with the file
    except IOError:
        messagebox.showinfo("Chaves", "Por favor, carregue as chaves para o diretorio atual OU crie um novo par de chaves!")
        msg = "Chaves Não Carregadas"
        keys_loaded.set('Chaves Não Carregadas')
        return keys_loaded,msg



def save_file(data):
    """Save the current file as a new file."""
    filepath = asksaveasfilename(
        defaultextension="bin",
        filetypes=[("Text Files", "*.bin"), ("All Files", "*.*")],
    )
    if not filepath:
        return
    with open(filepath, "wb") as output_file:
        text = txt_edit.get(1.0, tk.END)
        output_file.write(text)
    window.title(f"Text Editor Application - {filepath}")



def size_12():
   txt_edit.config(font=('Helvatical bold',12))

def size_20():
   txt_edit.config(font=('Helvetica bold',20))





window = tk.Tk()
window.title("Text Editor Application")
window.rowconfigure(0, minsize=800, weight=1)
window.columnconfigure(1, minsize=800, weight=1)


keys_loaded = check_keys()



txt_edit = tk.Text(window)

fr_buttons = tk.Frame(window, relief=tk.RAISED, bd=3)
#btn_open = tk.Button(fr_buttons, text="Open", command=open_file)
#btn_save = tk.Button(fr_buttons, text="Save As...", command=save_file)
#text = txt_edit.read()


btn_encrypt = tk.Button(fr_buttons, text="Criptografar...", command=encrypt_step_1)
btn_decrypt = tk.Button(fr_buttons, text="Descriptografar...", command=decrypt_step_1)\

if keys_loaded[1] == "Chaves Carregadas":
    color = "green"
else:
    color = "red"

btn_create_key_pair = tk.Button(fr_buttons, text="Criar par de chaves ...", command=create_key_pair)




lbl_keys_loaded = tk.Label(fr_buttons,bg=color, text="", textvariable=keys_loaded[0])
lbl_font_size = tk.Label(fr_buttons, text="Font Size:")


button_size_12= Button(fr_buttons, text="12", command= size_12)
button_size_20= Button(fr_buttons, text="20", command= size_20)
#btn_open.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
#btn_save.grid(row=1, column=0, sticky="ew", padx=5)
btn_encrypt.grid(row=2, column=0, sticky="ew", padx=5)
btn_decrypt.grid(row=3, column=0, sticky="ew", padx=5)
btn_create_key_pair.grid(row=4, column=0, sticky="ew", padx=5)
lbl_keys_loaded.grid(row=7, column=0, sticky="ew", padx=5)

lbl_font_size.grid(row=8, column=0, sticky="ew", padx=5,pady=15)
button_size_12.grid(row=9, column=0, sticky="ew", padx=5)
button_size_20.grid(row=10, column=0, sticky="ew", padx=5)

fr_buttons.grid(row=0, column=0, sticky="ns")
txt_edit.grid(row=0, column=1, sticky="nsew")




window.mainloop()
