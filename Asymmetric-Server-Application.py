# -*- coding: utf-8 -*-
"""
Created on Tue March  26 08:345:47 2025

@author: IAN CARTER KULANI

"""

from colorama import Fore
import pyfiglet
import os
font=pyfiglet.figlet_format("Asymetric Server")
print(Fore.GREEN+font)

import socket
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hatmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# Function to generate RSA keys and save them
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_key = private_key.public_key()
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Save the keys to files
    with open('private_key.pem', 'wb') as private_file:
        private_file.write(private_pem)
        
    with open('public_key.pem', 'wb') as public_file:
        public_file.write(public_pem)
    
    return private_key, public_key

# Function to decrypt received messages
def decrypt_message(private_key, encrypted_message):
    original_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return original_message.decode()

# Setup server socket
def start_server():
    server_ip = input("Enter server IP: ")
    server_port = int(input("Enter server port: "))

    # Create and bind the server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((server_ip, server_port))
    server_socket.listen(5)

    print(f"Server listening on {server_ip}:{server_port}...")

    # Accept incoming client connection
    client_socket, client_address = server_socket.accept()
    print(f"Connection established with {client_address}")

    # Load server's private key
    with open('private_key.pem', 'rb') as private_file:
        private_key = serialization.load_pem_private_key(private_file.read(), password=None, backend=default_backend())

    # Receive the encrypted message from the client
    encrypted_message = client_socket.recv(1024)
    
    # Decrypt the message
    decrypted_message = decrypt_message(private_key, encrypted_message)
    print(f"Decrypted message from client: {decrypted_message}")
    
    # Send a response back to the client
    response = "Message received and decrypted"
    client_socket.send(response.encode())
    
    # Close the connection
    client_socket.close()
    server_socket.close()

if __name__ == "__main__":
    if not os.path.exists('private_key.pem') or not os.path.exists('public_key.pem'):
        generate_keys()
    
    start_server()
