import os
import tkinter as tk
from tkinter import filedialog
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from tkinter import ttk


def generate_key(password):
    password = password.encode()
    salt = b'salt_'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)


def pad_data(data):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

def unpad_data(padded_data):
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

def encrypt_file(input_file, output_file, password):
    with open(input_file, 'rb') as file:
        data = file.read()

    key = generate_key(password)
    data = pad_data(data)  

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()

    with open(output_file, 'wb') as file:
        file.write(iv + encrypted_data)

def decrypt_file(input_file, output_file, password):
    with open(input_file, 'rb') as file:
        encrypted_data = file.read()

    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]

    key = generate_key(password)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    decrypted_data = unpad_data(decrypted_data)  

    if not encrypt.get():
        filename, _ = os.path.splitext(output_file)
        output_file = filename

    with open(output_file, 'wb') as file:
        file.write(decrypted_data)
        

def browse_input_file():
    input_file_path = filedialog.askopenfilename()
    input_file_entry.delete(0, tk.END)
    input_file_entry.insert(0, input_file_path)

def browse_output_file():
    output_file_path = filedialog.asksaveasfilename(defaultextension='.enc')
    output_file_entry.delete(0, tk.END)
    output_file_entry.insert(0, output_file_path)

def encrypt_decrypt_file():
    input_file = input_file_entry.get()
    output_file = output_file_entry.get()
    password = password_entry.get()

    if encrypt.get() == 1:
        encrypt_file(input_file, output_file, password)
    else:
        decrypt_file(input_file, output_file, password)

    status_label.config(text='Operation completed.')

app = tk.Tk()
app.title('Text File Encryption/Decryption using AES with PKCS7 Padding')
app.geometry('500x260')


app.configure(bg='black')

input_file_label = tk.Label(app, text='Input File:', bg='black', fg='white')
input_file_label.pack()

input_file_entry = tk.Entry(app, width=40)
input_file_entry.pack()

browse_input_button = tk.Button(app, text='Browse', command=browse_input_file, bg='black', fg='white')
browse_input_button.pack()

output_file_label = tk.Label(app, text='Output File:', bg='black', fg='white')
output_file_label.pack()

output_file_entry = tk.Entry(app, width=40)
output_file_entry.pack()

browse_output_button = tk.Button(app, text='Browse', command=browse_output_file, bg='black', fg='white')
browse_output_button.pack()

password_label = tk.Label(app, text='Password:', bg='black', fg='white')
password_label.pack()

password_entry = tk.Entry(app, show='*', width=40)
password_entry.pack()

encrypt = tk.IntVar()
encrypt_check_button = ttk.Checkbutton(app, text='Encrypt', variable=encrypt, onvalue=1, offvalue=0, style='TCheckbutton', cursor='hand2')
encrypt_check_button.pack()

decrypt_check_button = ttk.Checkbutton(app, text='Decrypt', variable=encrypt, onvalue=2, offvalue=0, style='TCheckbutton', cursor='hand2')
decrypt_check_button.pack()

encrypt.set(1)

encrypt_decrypt_button = tk.Button(app, text='Encrypt/Decrypt', command=encrypt_decrypt_file, bg='black', fg='white')
encrypt_decrypt_button.pack()

status_label = tk.Label(app, text='', bg='black', fg='white')
status_label.pack()


style = ttk.Style()
style.configure('TCheckbutton', background='black', foreground='white')

app.mainloop()
