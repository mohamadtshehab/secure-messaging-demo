from scripts.server import Server
from scripts.client import Client

def main():
    choice = input("Run as (server/client): ").strip().lower()
    encryption = input("encryption? (symmetric/asymmetric/none): ").strip().lower()
    
    if choice == 'server':
        server = Server(mode=encryption)
        if encryption == 'symmetric':
            server.symmetric_key = server.generate_symmetric_key()
            server.save_symmetric_key()
        elif encryption == 'asymmetric':
            private_key = server.generate_private_key()
            server.private_key = private_key
            server.public_key = server.generate_public_key(private_key)
            server.save_public_key()
        server.start_connection()

    elif choice == 'client':
        client = Client(mode=encryption)
        if encryption == 'symmetric':
            client.symmetric_key = client.read_symmetric_key()
        elif encryption == 'asymmetric':
            private_key = client.generate_private_key()
            client.private_key = private_key
            client.public_key = client.generate_public_key(private_key)
            client.save_public_key()
            pass
        client.connect()
    else:
        print("Invalid choice. Please choose 'server' or 'client'.")


if __name__ == '__main__':
    main()