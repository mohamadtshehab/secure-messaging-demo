from scripts.messenger import BasicMessenger
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
import ssl
import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class Server(BasicMessenger):
    def generate_symmetric_key(self):
        # Generate a symmetric encryption key
        key = Fernet.generate_key()
        return key

    def save_symmetric_key(self):
        # Save the symmetric key to a file for later use
        symmetric_key = self.symmetric_key
        with open('keys.txt', 'w') as file:
            file.write(symmetric_key.decode())

    def start_connection(self):
        # Set up SSL context and start listening for client connections
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile='server.crt', keyfile='server.key')

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(1)

        print(f"Server listening on {self.host}:{self.port}")

        client_socket, address = self.server_socket.accept()
        secure_socket = context.wrap_socket(client_socket, server_side=True)
        print(f"Connected to {address}")
        self.handle_messaging(secure_socket)

    def handle_messaging(self, channel):
        # Route the messaging to the appropriate encryption mode handler
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
        # Handle unencrypted communication with the client
        while True:
            received_message = channel.recv(4096)
            if not received_message:
                break
            decoded_message = received_message.decode()
            print(f"Client: {decoded_message}")

            response = input("Reply: ")
            encoded_message = response.encode()
            channel.sendall(encoded_message)

    def handle_symmetric_messaging(self, channel):
        # Handle encrypted communication using symmetric encryption
        while True:
            received_message = channel.recv(4096)
            if not received_message:
                break
            decrypted_message = self.decrypt_symmetric(received_message)
            print(f"Client: {decrypted_message}")

            response = input("Reply: ")
            encrypted_response = self.encrypt_symmetric(response)
            channel.sendall(encrypted_response)

    def handle_asymmetric_messaging(self, channel):
        # Handle encrypted communication using asymmetric encryption
        client_public_key = self.read_client_public_key()
        while True:
            received_message = channel.recv(4096)
            if not received_message:
                break
            decrypted_message = self.decrypt_asymmetric(received_message)
            print(f"Client: {decrypted_message}")

            response = input("Reply: ")
            encrypted_response = self.encrypt_asymmetric(response, client_public_key)
            channel.sendall(encrypted_response)

    def save_public_key(self):
        # Save the server's public key to a file for sharing with the client
        public_key = self.public_key
        with open('server_public_keys.txt', 'w') as file:
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            file.write(pem.decode())

    def read_client_public_key(self):
        # Load the client's public key from a file for encryption
        with open('client_public_keys.txt', 'r') as file:
            string_key = file.read().strip()
            if not string_key:
                raise ValueError('Public key was not found in the client public keys file.')
            bytes_key = string_key.encode('utf-8')
            key = serialization.load_pem_public_key(bytes_key)
            return key
