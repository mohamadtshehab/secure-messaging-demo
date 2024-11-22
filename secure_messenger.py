# Path: secure_messenger.py
import socket
import threading
import ssl
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

class SecureMessenger:
    def __init__(self, host='localhost', port=65432):
        self.host = host
        self.port = port
        self.symmetric_key = None
        self.private_key = None
        self.public_key = None
        self.remote_public_key = None
        self.encryption_mode = 'none'

    def generate_symmetric_key(self):
        return Fernet.generate_key()

    def generate_asymmetric_keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def encrypt_symmetric(self, message):
        if not self.symmetric_key:
            raise ValueError("Symmetric key not set")
        f = Fernet(self.symmetric_key)
        return f.encrypt(message.encode())

    def decrypt_symmetric(self, encrypted_message):
        if not self.symmetric_key:
            raise ValueError("Symmetric key not set")
        f = Fernet(self.symmetric_key)
        return f.decrypt(encrypted_message).decode()

    def encrypt_asymmetric(self, message):
        if not self.remote_public_key:
            raise ValueError("Remote public key not set")
        encrypted = self.remote_public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted

    def decrypt_asymmetric(self, encrypted_message):
        if not self.private_key:
            raise ValueError("Private key not set")
        decrypted = self.private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode()

class Server(SecureMessenger):
    def start_server(self):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile='server.crt', keyfile='server.key')

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(1)
        
        print(f"Server listening on {self.host}:{self.port}")
        
        client_socket, address = self.server_socket.accept()
        secure_socket = context.wrap_socket(client_socket, server_side=True)
        
        print(f"Connected to {address}")
        self.handle_connection(secure_socket)

    def handle_connection(self, connection):
        try:
            # Exchange public keys
            self.generate_asymmetric_keys()
            server_public_key_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            connection.sendall(server_public_key_bytes)
            print("Sent server's public key.")

            client_public_key_bytes = connection.recv(4096)
            self.remote_public_key = serialization.load_pem_public_key(client_public_key_bytes)
            print("Received client's public key.")

            # Generate symmetric key and send it securely
            self.symmetric_key = self.generate_symmetric_key()
            encrypted_symmetric_key = self.encrypt_asymmetric(self.symmetric_key.decode())
            connection.sendall(encrypted_symmetric_key)
            print("Sent encrypted symmetric key.")

            # Continue with encrypted communication
            while True:
                data = connection.recv(4096)
                if not data:
                    break
                decrypted_message = self.decrypt_symmetric(data)
                print(f"Client: {decrypted_message}")

                response = input("Reply: ")
                encrypted_response = self.encrypt_symmetric(response)
                connection.sendall(encrypted_response)
        finally:
            connection.close()

class Client(SecureMessenger):
    def connect(self):
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        secure_socket = context.wrap_socket(self.client_socket)
        secure_socket.connect((self.host, self.port))
        
        print("Connected to server.")
        self.handle_connection(secure_socket)

    def handle_connection(self, connection):
        try:
            # Exchange public keys
            self.generate_asymmetric_keys()
            server_public_key_bytes = connection.recv(4096)
            self.remote_public_key = serialization.load_pem_public_key(server_public_key_bytes)
            print("Received server's public key.")

            client_public_key_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            connection.sendall(client_public_key_bytes)
            print("Sent client's public key.")

            # Receive encrypted symmetric key and decrypt it
            encrypted_symmetric_key = connection.recv(4096)
            self.symmetric_key = self.decrypt_asymmetric(encrypted_symmetric_key).encode()
            print("Received and decrypted symmetric key.")

            # Continue with encrypted communication
            while True:
                message = input("Message: ")
                encrypted_message = self.encrypt_symmetric(message)
                connection.sendall(encrypted_message)

                data = connection.recv(4096)
                if not data:
                    break
                decrypted_message = self.decrypt_symmetric(data)
                print(f"Server: {decrypted_message}")
        finally:
            connection.close()


def main():
    print("Secure Messenger")
    mode = input("Choose mode (server/client): ").lower()
    encryption = input("Choose encryption (symmetric/asymmetric/none): ").lower()

    messenger = Server() if mode == 'server' else Client()
    messenger.encryption_mode = encryption

    if encryption == 'symmetric':
        messenger.symmetric_key = messenger.generate_symmetric_key()
        print(f"Symmetric key: {messenger.symmetric_key.decode()}")
    elif encryption == 'asymmetric':
        messenger.generate_asymmetric_keys()
        print("Asymmetric keys generated.")

    if mode == 'server':
        messenger.start_server()
    else:
        messenger.connect()

if __name__ == '__main__':
    main()
