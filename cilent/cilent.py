import socket
import ssl
import threading
from datetime import datetime
import sys
sys.path.append("/crypt.py")
from crypt import EcdhAesCrypt, Curve25519Sm4
from cryptography.hazmat.primitives import serialization



def send_message(client_socket, ae_shared_key, cs_shared_key):
    cs = Curve25519Sm4()
    while True:
        message = input("客户端: ")
        if message.lower() == 'exit':
            break
        encrypted_message = EcdhAesCrypt.encrypt_data(ae_shared_key, message)
        encrypted_message = cs.encrypt_ecb(cs_shared_key, encrypted_message)
        client_socket.send(encrypted_message.encode("utf-8"))

def receive_message(client_socket, ae_shared_key, cs_shared_key):
    cs = Curve25519Sm4()
    while True:
        response = client_socket.recv(1024)
        decrypted_message = cs.decrypt_ecb(cs_shared_key, response)
        decrypted_message = EcdhAesCrypt.decrypt_data(ae_shared_key, decrypted_message)
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
    cilent_cs = Curve25519Sm4()
    client_cs_private_key, client_cs_public_key = cilent_cs.get_private_key(), cilent_cs.get_public_key()

    print("客户端EA公钥:", client_public_key, "类型",type(client_public_key))
    print("客户端CS公钥:", client_cs_public_key, "类型",type(client_cs_public_key))

    # 发送客户端EA公钥
    client_socket.send(client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

    # 发送客户端CS公钥
    client_socket.send(client_cs_public_key)  # 直接发送字节数据

    # 接收服务器的EA公钥
    server_public_key_data = client_socket.recv(1024)
    server_public_key = serialization.load_pem_public_key(server_public_key_data)

    # 接收服务器的CS公钥
    server_cs_public_key = client_socket.recv(1024)

    # 计算共享EA密钥
    client_shared_ae_key = EcdhAesCrypt.generate_shared_key(client_private_key, server_public_key)

    # 计算共享CS密钥
    client_shared_cs_key = cilent_cs.generate_shared_key(server_cs_public_key).hex()

    # 启动两个线程分别处理发送和接收
    threading.Thread(target=send_message, args=(client_socket, client_shared_ae_key, client_shared_cs_key), daemon=True).start()
    threading.Thread(target=receive_message, args=(client_socket, client_shared_ae_key, client_shared_cs_key), daemon=True).start()

    while True:
        pass  # 保持主线程运行

if __name__ == "__main__":
    try:
        start_client()
    except Exception as e:
        print(f"ERROR: {e}")
