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
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', 5500))
    sock.listen(1)
    print("Serverul așteaptă conexiuni pe portul 5500...")

    client, addr = sock.accept()
    print(f"Conexiune acceptată de la {addr}.")

    public_key, private_key = generate_rsa_keys()
    print("Cheia publică RSA server:", public_key.save_pkcs1('PEM').decode())
    print("Cheia privată RSA server:", private_key.save_pkcs1('PEM').decode())

    public_key_pem = public_key.save_pkcs1('PEM')
    send_message(client, public_key_pem)

    client_public_key_pem = receive_message(client)
    client_public_key = rsa.PublicKey.load_pkcs1(client_public_key_pem)
    print("Cheia publică RSA client recepționată și încărcată.")

    symmetric_key = Fernet.generate_key()
    print(f"Cheia simetrică generată: {symmetric_key.decode()}")
    fernet = Fernet(symmetric_key)
    encrypted_key = rsa.encrypt(symmetric_key, client_public_key)
    send_message(client, encrypted_key)
    print("Cheia simetrică Fernet a fost criptată și trimisă.")

    fingerprint = generate_fingerprint(client_public_key_pem)

    try:
        while True:
            message = receive_message(client)
            decrypted_message = fernet.decrypt(message)
            print(f"Mesaj decriptat: {decrypted_message.decode()}")

            response = input('Răspunsul serverului> ')
            encrypted_response = fernet.encrypt(response.encode())
            print(f"Mesaj de răspuns criptat: {encrypted_response}")
            send_message(client, encrypted_response)
    except Exception as e:
        print(f"Eroare în timpul comunicării: {e}")
    finally:
        client.close()
        sock.close()

if __name__ == "__main__":
    main()
