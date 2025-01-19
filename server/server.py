import socket
import threading
import ssl
from datetime import datetime
import sys
sys.path.append("/crypt.py")
from crypt import EcdhAesCrypt, Curve25519Sm4
from cryptography.hazmat.primitives import serialization
import subprocess



PS_COMMAND = 'Stop-Process -Id (Get-NetTCPConnection -LocalPort 52000).OwningProcess'
PWSH_PATH = "C:/Program Files/PowerShell/7/pwsh.exe"
# 先关闭占用 52000 端口的进程
result = subprocess.run([PWSH_PATH, 'powershell', '-Command', PS_COMMAND], capture_output=True, text=True)


def handle_client(conn, addr):
    print(f"建立连接: {addr}")

    # 生成服务器的 ECC 密钥对
    server_private_key, server_public_key = EcdhAesCrypt.generate_ecc_keypair()
    server_cs = Curve25519Sm4()
    server_cs_private_key, server_cs_public_key = server_cs.get_private_key(), server_cs.get_public_key()
    print("服务器EA公钥:", server_public_key, "类型", type(server_public_key))
    print("服务器CS公钥:", server_cs_public_key, "类型", type(server_cs_public_key))

    # 发送服务器EA公钥给客户端
    conn.send(server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

    # 发送服务器CS公钥给客户端
    conn.send(server_cs_public_key)


    # 接收客户端的EA公钥
    client_public_key_data = conn.recv(1024)
    client_public_key = serialization.load_pem_public_key(client_public_key_data)

    # 接收客户端的CS公钥
    client_cs_public_key = conn.recv(1024)

    # 计算共享EA密钥
    server_shared_key = EcdhAesCrypt.generate_shared_key(server_private_key, client_public_key)

    # 计算共享CS密钥
    server_cs_shared_key = server_cs.generate_shared_key(client_cs_public_key).hex()

    def receive_message():
        cs = Curve25519Sm4()
        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    print("客户端断开连接.")
                    break
                decrypted_data = cs.decrypt_ecb(server_cs_shared_key, data)
                decrypted_data = EcdhAesCrypt.decrypt_data(server_shared_key, decrypted_data)
                print(f"\n客户端: {decrypted_data}", datetime.now())
            except ConnectionResetError:
                print("客户端重置连接.")
                break

    def send_message():
        cs = Curve25519Sm4()
        while True:
            response = input("服务端: ")
            if response.lower() == 'exit':
                break
            encrypted_response = EcdhAesCrypt.encrypt_data(server_shared_key, response)
            encrypted_response = cs.encrypt_ecb(server_cs_shared_key,encrypted_response)
            conn.send(encrypted_response.encode('utf-8'))

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
