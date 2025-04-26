import os
import socket
import sys
import threading
from nacl.public import PrivateKey, Box, PublicKey
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

PORT = 2019

def print_received_message(message: str, chat_correspondent_ip: str):
    sys.stdout.write("\r")  # move cursor to the beginning of the line
    sys.stdout.write(chat_correspondent_ip + ": " + message + "\n")  # print the message 
    sys.stdout.write("> ")  # print the prompt again
    sys.stdout.flush()  # flush the output buffer

def handle_connection(chat_socket: socket.socket, chat_correspondent_ip: str, verify_key: VerifyKey, aes_key: bytes):
    while True:
        signed_encrypted_message: bytes = chat_socket.recv(1024)
        if not signed_encrypted_message:
            break

        try:
            encrypted_message = verify_key.verify(signed_encrypted_message)
        except BadSignatureError:
            print("Received message with invalid signature")
            return

        try:
            # Receiver side (Decryption)
            iv: bytes = encrypted_message[:16]  # Extract the IV (first 16 bytes)
            ciphertext = encrypted_message[16:]  # The rest is ciphertext
        except IndexError:
            print("Received message with invalid format")
            return

        # Decrypt the message
        decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend()).decryptor()
        padded_message = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_message = unpadder.update(padded_message) + unpadder.finalize()

        print_received_message(decrypted_message.decode('utf-8'), chat_correspondent_ip)
    
def get_private_ip():
    # This doesn't need to actually reach the internet
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            # Connect to a dummy address (Google DNS, won't actually send data) 
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"  # Fallback to localhost if anything goes wrong
        
def encrypt_message(message: str, aes_key: bytes) -> bytes:
    # Pad the message to the block size
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode('utf-8')) + padder.finalize()

    # Encrypt the message
    iv = os.urandom(16)   # AES block size IV (16 bytes)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    encrypted_message = iv + ciphertext

    return encrypted_message


def main():
    # Generate a new random signing (private) key
    private_key: PrivateKey = PrivateKey.generate()
    # Get the corresponding verify (public) key
    public_key = private_key.public_key
    # Generate a signing key and the corresponding verify key
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key

    print(f"Your public key: {public_key.encode().hex()}")
    print(f"Your verify key: {verify_key.encode().hex()}")

    print("What is your correspondent's public key?")
    correspondent_public_key: PublicKey = PublicKey(bytes.fromhex(input()))
    encryption_box = Box(private_key, correspondent_public_key)

    print("Server? (y/n)")
    is_server = "y" == input().lower()

    chat_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    chat_correspondent_ip = None

    if is_server:
        chat_socket.bind((get_private_ip(), PORT))  # Replace with Client 1's IP address  
        chat_socket.listen(1)
        chat_socket, address = chat_socket.accept()
        chat_correspondent_ip = str(address)
    else:
        print("IP adress of correspondent:")
        chat_correspondent_ip = input()
        chat_socket.connect((chat_correspondent_ip, PORT))  # Replace with Client 2's IP address and port
    print(f"Connected to {chat_correspondent_ip}")

    if is_server:
        print("Waiting for AES-256 key...")
        encrypted_aes_key = chat_socket.recv(1024)
        aes_key: bytes = encryption_box.decrypt(encrypted_aes_key)
        print("Received AES-256 key")
    else:
        aes_key: bytes = os.urandom(32)
        encrypted_aes_key: bytes = encryption_box.encrypt(aes_key)
        chat_socket.sendall(encrypted_aes_key)
        print("Sent AES-256 key")

    encrypted_verify_key: bytes = encryption_box.encrypt(bytes(verify_key))
    chat_socket.sendall(encrypted_verify_key)
    print("Waiting for verify key...")
    encrypted_verify_key = chat_socket.recv(1024)
    correspondent_verify_key: VerifyKey = VerifyKey(encryption_box.decrypt(encrypted_verify_key))
    print("Received verify key: " + correspondent_verify_key.encode().hex())
    print("Safe channel is established")

    threading.Thread(target=handle_connection, args=(chat_socket, chat_correspondent_ip, correspondent_verify_key, aes_key)).start()

    while True:
        message = input("> ")
        encrypted_message: bytes = encrypt_message(message, aes_key)
        signed_encrypted_message: bytes = signing_key.sign(encrypted_message)
        chat_socket.sendall(signed_encrypted_message)

if __name__ == "__main__":
    main()
