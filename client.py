import socket
import rsa
from cryptography.fernet import Fernet
from hashlib import sha256

def generate_rsa_keys():
    public_key, private_key = rsa.newkeys(2048)
    print("Cheile RSA generate: Publică și Privată.")
    return public_key, private_key

def generate_fingerprint(data):
    fingerprint = sha256(data).hexdigest()[:10]
    print(f"Fingerprint generat pentru date: {fingerprint}")
    return fingerprint

def send_message(sock, data):
    print(f"Se trimite mesaj de lungime: {len(data)} bytes")
    sock.send(len(data).to_bytes(4, byteorder='big') + data)

def receive_message(sock):
    length = int.from_bytes(sock.recv(4), byteorder='big')
    data = sock.recv(length)
    print(f"Primit mesaj de lungime: {length} bytes")
    return data

def main():
    host = input('Adresa host pentru conectare: ').strip()
    port = int(input('Portul pentru conectare: ').strip())

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    print(f"Conexiune stabilită cu serverul la {host}:{port}")

    public_key, private_key = generate_rsa_keys()
    print("Cheia publică RSA client:", public_key.save_pkcs1('PEM').decode())
    print("Cheia privată RSA client:", private_key.save_pkcs1('PEM').decode())

    public_key_pem = public_key.save_pkcs1('PEM')
    send_message(sock, public_key_pem)

    server_public_key_pem = receive_message(sock)
    server_public_key = rsa.PublicKey.load_pkcs1(server_public_key_pem)
    print("Cheia publică RSA server recepționată și încărcată.")

    encrypted_key = receive_message(sock)
    symmetric_key = rsa.decrypt(encrypted_key, private_key)
    fernet = Fernet(symmetric_key)
    print(f"Cheia simetrică Fernet decriptată și gata de utilizare: {symmetric_key.decode()}")

    fingerprint = generate_fingerprint(server_public_key_pem)

    try:
        while True:
            message = input('Mesajul clientului> ')
            encrypted_message = fernet.encrypt(message.encode())
            print(f"Mesaj criptat trimis la server: {encrypted_message}")
            send_message(sock, encrypted_message)

            server_response = receive_message(sock)
            decrypted_response = fernet.decrypt(server_response)
            print(f"Mesaj decriptat de la server: {decrypted_response.decode()}")
    except Exception as e:
        print(f"Eroare în timpul comunicării: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
