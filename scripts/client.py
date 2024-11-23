from scripts.messenger import BasicMessenger
from cryptography.hazmat.primitives import serialization
import ssl
import socket

class Client(BasicMessenger):
    def read_symmetric_key(self):
        # Read symmetric key from a file for encryption/decryption
        with open('keys.txt', 'r') as file:
            key = file.read().strip().encode()
            if not key:
                raise ValueError('Symmetric key was not found in the keys file.')
            return key

    def connect(self):
        # Establish a secure SSL connection to the server
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        secure_socket = context.wrap_socket(self.client_socket)
        secure_socket.connect((self.host, self.port))

        print("Connected to server.")
        self.handle_connection(secure_socket)

    def handle_connection(self, channel):
        # Route connection to the appropriate encryption mode handler
        try:
            if self.mode == 'none':
                self.handle_plain_messaging(channel)
            elif self.mode == 'symmetric':
                self.handle_symmetric_messaging(channel)
            elif self.mode == 'asymmetric':
                self.handle_asymmetric_messaging(channel)
            else:
                raise ValueError('Not a valid encryption.')
        finally:
            channel.close()

    def handle_plain_messaging(self, channel):
        # Handle unencrypted communication with the server
        while True:
            message = input("Message: ").encode()
            channel.sendall(message)

            received_message = channel.recv(4096)
            if not received_message:
                break
            decoded_message = received_message.decode()
            print(f"Server: {decoded_message}")

    def handle_symmetric_messaging(self, channel):
        # Handle encrypted communication using symmetric encryption
        while True:
            message = input("Message: ")
            encrypted_message = self.encrypt_symmetric(message)
            channel.sendall(encrypted_message)

            received_message = channel.recv(4096)
            if not received_message:
                break
            decrypted_message = self.decrypt_symmetric(received_message)
            print(f"Server: {decrypted_message}")

    def handle_asymmetric_messaging(self, channel):
        # Handle encrypted communication using asymmetric encryption
        server_public_key = self.read_server_public_key()
        while True:
            message = input("Message: ")
            encrypted_message = self.encrypt_asymmetric(message, server_public_key)
            channel.sendall(encrypted_message)

            received_message = channel.recv(4096)
            if not received_message:
                break
            decrypted_message = self.decrypt_asymmetric(received_message)
            print(f"Server: {decrypted_message}")

    def read_server_public_key(self):
        # Load the server's public key from a file for encryption
        with open('server_public_keys.txt', 'r') as file:
            string_key = file.read().strip()
            if not string_key:
                raise ValueError('Public key was not found in the server public keys file.')
            bytes_key = string_key.encode('utf-8')
            key = serialization.load_pem_public_key(bytes_key)
            return key

    def save_public_key(self):
        # Save the client's public key to a file for sharing with the server
        public_key = self.public_key
        with open('client_public_keys.txt', 'w') as file:
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            file.write(pem.decode())
