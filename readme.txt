how to run this code?

install 'cryptography'

run the following command in a shell window:
    openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes

open a new terminal and run the command:
    python main.py
choose 'server' then one of the 3 encryption methods

open a new terminal and run the command:
choose 'client' then the same encryption method above
