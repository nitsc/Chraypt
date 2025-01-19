import socket
import threading
import ssl
from datetime import datetime
import sys
sys.path.append("/crypt.py")
from crypt import EcdhAesCrypt
from cryptography.hazmat.primitives import serialization



def handle_client(conn, addr):
    print(f"建立连接: {addr}")

    # 生成服务器的 ECC 密钥对
    server_private_key, server_public_key = EcdhAesCrypt.generate_ecc_keypair()
    print("服务器公钥:", server_public_key)

    # 发送服务器公钥给客户端
    conn.send(server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

    # 接收客户端的公钥
    client_public_key_data = conn.recv(1024)
    client_public_key = serialization.load_pem_public_key(client_public_key_data)

    # 计算共享密钥
    server_shared_key = EcdhAesCrypt.generate_shared_key(server_private_key, client_public_key)

    def receive_message():
        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    print("客户端断开连接.")
                    break
                decrypted_data = EcdhAesCrypt.decrypt_data(server_shared_key, data)
                print(f"\n客户端: {decrypted_data}", datetime.now())
            except ConnectionResetError:
                print("客户端重置连接.")
                break

    def send_message():
        while True:
            response = input("服务端: ")
            if response.lower() == 'exit':
                break
            encrypted_response = EcdhAesCrypt.encrypt_data(server_shared_key, response)
            conn.send(encrypted_response)

    threading.Thread(target=receive_message, daemon=True).start()
    threading.Thread(target=send_message, daemon=True).start()

    while True:
        pass

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 52000))
    server_socket.listen(1)
    print("服务端在端口 52000 监听...")

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="D:/chraypt/server/pems/certfile.crt", keyfile="D:/chraypt/server/pems/keyfile.key")

    server_socket = context.wrap_socket(server_socket, server_side=True)

    while True:
        conn, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    try:
        start_server()
    except Exception as e:
        print(f"ERROR: {e}")
