from cryptography.fernet import Fernet
import ssl
import socket


class BasicMessenger:
    def __init__(self, host='localhost', port=65432, use_encryption=True):
        self.symmetric_key = None
        self.host = host
        self.port = port
        self.server_socket = None
        self.client_socket = None
        self.use_encryption = use_encryption  # Toggle encryption

    def set_symmetric_key(self, key):
        self.symmetric_key = key

    def get_symmetric_key(self):
        return self.symmetric_key

    def encrypt_symmetric(self, message):
        if not self.use_encryption:
            return message.encode()  # Return raw bytes if encryption is off
        if not self.symmetric_key:
            raise ValueError("Symmetric key is not set.")
        fernet = Fernet(self.get_symmetric_key())
        encrypted_message = fernet.encrypt(message.encode())  # Encode string to bytes for Fernet
        return encrypted_message

    def decrypt_symmetric(self, encrypted_message):
        if not self.use_encryption:
            return encrypted_message.decode()  # Decode raw bytes to string if encryption is off
        if not self.symmetric_key:
            raise ValueError("Symmetric key is not set.")
        fernet = Fernet(self.get_symmetric_key())
        decrypted_message = fernet.decrypt(encrypted_message)
        string_message = decrypted_message.decode()  # Decode bytes to string
        return string_message


class Server(BasicMessenger):
    def generate_symmetric_key(self):
        key = Fernet.generate_key()
        return key

    def save_symmetric_key(self):
        symmetric_key = self.get_symmetric_key()
        with open('keys.txt', 'w') as file:
            file.write(symmetric_key.decode())

    def start_connection(self):
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
        try:
            while True:
                received_message = channel.recv(4096)
                if not received_message:
                    break
                decrypted_message = self.decrypt_symmetric(received_message)
                print(f"Client: {decrypted_message}")

                response = input("Reply: ")
                encrypted_response = self.encrypt_symmetric(response)
                channel.sendall(encrypted_response)
        finally:
            channel.close()


class Client(BasicMessenger):
    def read_symmetric_key(self):
        with open('keys.txt', 'r') as file:
            key = file.read().strip().encode()
            if not key:
                raise ValueError('Symmetric key was not found in the keys file.')
            return key

    def connect(self):
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        secure_socket = context.wrap_socket(self.client_socket)
        secure_socket.connect((self.host, self.port))

        print("Connected to server.")
        self.handle_connection(secure_socket)

    def handle_connection(self, channel):
        try:
            while True:
                message = input("Message: ")
                encrypted_message = self.encrypt_symmetric(message)
                channel.sendall(encrypted_message)

                received_message = channel.recv(4096)
                if not received_message:
                    break
                decrypted_message = self.decrypt_symmetric(received_message)
                print(f"Server: {decrypted_message}")
        finally:
            channel.close()


def main():
    choice = input("Run as (server/client): ").strip().lower()
    use_encryption = input("Use encryption? (yes/no): ").strip().lower() == 'yes'
    
    if choice == 'server':
        server = Server(use_encryption=use_encryption)
        if use_encryption:
            server.set_symmetric_key(server.generate_symmetric_key())
            server.save_symmetric_key()
        server.start_connection()

    elif choice == 'client':
        client = Client(use_encryption=use_encryption)
        if use_encryption:
            client.set_symmetric_key(client.read_symmetric_key())
        client.connect()
    else:
        print("Invalid choice. Please choose 'server' or 'client'.")


if __name__ == '__main__':
    main()
