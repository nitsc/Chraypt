import socket
import ssl
import threading
from datetime import datetime
import sys
sys.path.append("/crypt.py")
from crypt import EcdhAesCrypt
from cryptography.hazmat.primitives import serialization
import urllib.request



def send_message(client_socket, shared_key):
    while True:
        message = input("客户端: ")
        if message.lower() == 'exit':
            break
        encrypted_message = EcdhAesCrypt.encrypt_data(shared_key, message)
        client_socket.send(encrypted_message)

def receive_message(client_socket, shared_key):
    while True:
        response = client_socket.recv(1024)
        decrypted_message = EcdhAesCrypt.decrypt_data(shared_key, response)
        print(f"\n服务器: {decrypted_message}", datetime.now())

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_ip = input("输入服务端的 IP 地址: ")

    client_socket.connect((server_ip, 52000))
    context = ssl.create_default_context()
    context.check_hostname = False  # 禁用主机名检查
    context.verify_mode = ssl.CERT_NONE  # 禁用证书验证
    client_socket = context.wrap_socket(client_socket, server_hostname=server_ip)

    # 创建客户端的 ECC 密钥对Q
    client_private_key, client_public_key = EcdhAesCrypt.generate_ecc_keypair()
    print("客户端公钥:", client_public_key)

    # 发送客户端公钥给服务器
    client_socket.send(client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

    # 接收服务器的公钥
    server_public_key_data = client_socket.recv(1024)
    server_public_key = serialization.load_pem_public_key(server_public_key_data)

    # 计算共享密钥
    client_shared_key = EcdhAesCrypt.generate_shared_key(client_private_key, server_public_key)

    # 启动两个线程分别处理发送和接收
    threading.Thread(target=send_message, args=(client_socket, client_shared_key), daemon=True).start()
    threading.Thread(target=receive_message, args=(client_socket, client_shared_key), daemon=True).start()

    while True:
        pass  # 保持主线程运行

if __name__ == "__main__":
    try:
        start_client()
    except Exception as e:
        print(f"ERROR: {e}")
