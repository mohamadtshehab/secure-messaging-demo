# Import necessary libraries for logging, cryptography, and networking
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Configure logging for debugging and diagnostics
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class BasicMessenger:
    def __init__(self, host='localhost', port=65432, mode='none'):
        # Initialize messenger attributes, including networking and encryption settings
        self.symmetric_key = None
        self.host = host
        self.port = port
        self.server_socket = None
        self.client_socket = None
        self.mode = mode
        self.private_key = None
        self.public_key = None

    def encrypt_symmetric(self, message):
        # Encrypt a message using symmetric encryption (Fernet)
        if not self.symmetric_key:
            raise ValueError("Symmetric key is not set.")
        logging.debug(f"Encrypting message symmetrically: {message}")
        fernet = Fernet(self.symmetric_key)
        encrypted_message = fernet.encrypt(message.encode())
        logging.debug(f"Encrypted message: {encrypted_message}")
        return encrypted_message

    def decrypt_symmetric(self, encrypted_message):
        # Decrypt a message using symmetric encryption (Fernet)
        if not self.symmetric_key:
            raise ValueError("Symmetric key is not set.")
        logging.debug(f"Decrypting message symmetrically: {encrypted_message}")
        fernet = Fernet(self.symmetric_key)
        decrypted_message = fernet.decrypt(encrypted_message)
        string_message = decrypted_message.decode()
        logging.debug(f"Decrypted message: {string_message}")
        return string_message

    def generate_private_key(self):
        # Generate an RSA private key for asymmetric encryption
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        return private_key

    def generate_public_key(self, private_key):
        # Generate an RSA public key from the private key
        public_key = private_key.public_key()
        return public_key

    def encrypt_asymmetric(self, message, public_key):
        # Encrypt a message using the RSA public key
        logging.debug(f"Encrypting message asymmetrically: {message}")
        encrypted_message = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        logging.debug(f"Encrypted message: {encrypted_message}")
        return encrypted_message

    def decrypt_asymmetric(self, encrypted_message):
        # Decrypt a message using the RSA private key
        logging.debug(f"Decrypting message asymmetrically: {encrypted_message}")
        decrypted_message = self.private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        string_message = decrypted_message.decode()
        logging.debug(f"Decrypted message: {string_message}")
        return string_message
