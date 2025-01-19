import pickle
import socket
import threading
import ssl
from collections import defaultdict
from datetime import datetime
import sys
sys.path.append("/crypt.py")
from crypt import EcdhAesCrypt, Curve25519Sm4, Ed25519, Hasher
from cryptography.hazmat.primitives import serialization
import subprocess
import time


# 存储哈希值
HASH = '''670419071f13552cb2cf41fee37e8245d59d2073c0f015e6ac4df4a3f6233dd6cf543bf1cc838c484ee1cb7759445f4a0e55cb45f460bff6caca7f01be03f346'''

# 存储每个IP的连接数
connection_count = defaultdict(int)
MAX_CONNECTIONS = 10

# 存储每个IP的最后一次发送时间
last_sent = defaultdict(lambda: 0)
SEND_INTERVAL = 0.2

# 存储 PS 命令
PS_COMMAND = 'Stop-Process -Id (Get-NetTCPConnection -LocalPort 52000).OwningProcess'
PWSH_PATH = "C:/Program Files/PowerShell/7/pwsh.exe"

# 先关闭占用 52000 端口的进程
result = subprocess.run([PWSH_PATH, 'powershell', '-Command', PS_COMMAND], capture_output=True, text=True)



def handle_client(conn, addr):
    current_time = time.time()

    # 检查当前IP的连接数
    if connection_count[addr[0]] >= MAX_CONNECTIONS:
        print(f"连接数超过限制，拒绝连接: {addr}")
        conn.close()
        return

    # 增加连接数
    connection_count[addr[0]] += 1

    print(f"建立连接: {addr}")

    if current_time - last_sent[addr[0]] < SEND_INTERVAL:
        print(f"发送频率过快，拒绝请求: {addr}")
        conn.close()
        return

    # 更新最后一次发送时间
    last_sent[addr[0]] =int(current_time)

    # 接收客户端的哈希后的密钥
    hashed_key = conn.recv(1024).decode('utf-8')
    if hashed_key != HASH:
        print("密钥验证失败")
        conn.close()

    print("密钥验证成功")

    # 生成服务器的 EA 密钥对
    server_private_key, server_public_key = EcdhAesCrypt.generate_ecc_keypair()

    # 生成服务器的 CS 密钥对
    server_cs = Curve25519Sm4()
    server_cs_private_key, server_cs_public_key = server_cs.get_private_key(), server_cs.get_public_key()

    # 生成服务器的 EdDSA 密钥对
    ed  = Ed25519()
    private_ed_key, public_ed_key = ed.serialize_private_key(), ed.serialize_public_key()

    print("服务器EA公钥:", server_public_key, "类型", type(server_public_key))
    print("服务器CS公钥:", server_cs_public_key, "类型", type(server_cs_public_key))
    print("服务器EdDSA公钥:", public_ed_key, "类型", type(public_ed_key))

    # 发送服务器EA公钥给客户端
    conn.send(server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

    # 发送服务器CS公钥给客户端
    conn.send(server_cs_public_key)

    # 发送服务器EdDSA公钥给客户端
    conn.send(public_ed_key)

    # 接收客户端的EA公钥
    client_public_key_data = conn.recv(1024)
    client_public_key = serialization.load_pem_public_key(client_public_key_data)

    # 接收客户端的CS公钥
    client_cs_public_key = conn.recv(1024)

    # 接收客户端的EdDSA公钥
    client_ed_public_key = conn.recv(1024)

    # 计算共享EA密钥
    server_shared_key = EcdhAesCrypt.generate_shared_key(server_private_key, client_public_key)

    # 计算共享CS密钥
    server_cs_shared_key = server_cs.generate_shared_key(client_cs_public_key).hex()

    def receive_message(cilent_ed_public_key):
        cs = Curve25519Sm4()
        ed = Ed25519()
        hs = Hasher()
        while True:
            try:
                data = pickle.loads(conn.recv(1024))
                encrypted_message = data[0]
                signature = data[1]
                message_hash = data[2]
                if not encrypted_message:
                    print("客户端断开连接.")
                    break
                decrypted_data = cs.decrypt_ecb(server_cs_shared_key, encrypted_message)
                decrypted_data = EcdhAesCrypt.decrypt_data(server_shared_key, decrypted_data)
                print("\n客户端未经检查: ",decrypted_data)
                if ed.verify_signature(signature, decrypted_data.encode("utf-8"),cilent_ed_public_key):
                    if hs.ab33_hash(decrypted_data) != message_hash:
                        print(f"\n客户端: {decrypted_data}", datetime.now())
                    else:
                        print("客户端消息似乎不完整.")
                else:
                    print("客户端消息签名验证失败.")
            except ConnectionResetError:
                print("客户端重置连接.")
                break

    def send_message():
        cs = Curve25519Sm4()
        ed = Ed25519()
        hs = Hasher()
        while True:
            response = input("服务端: ")
            if response.lower() == 'exit':
                break
            encrypted_response = EcdhAesCrypt.encrypt_data(server_shared_key, response)
            encrypted_response = cs.encrypt_ecb(server_cs_shared_key,encrypted_response)
            signature = ed.sign_message(response.encode("utf-8"))
            message_hash = hs.ab33_hash(response)
            con_message = (encrypted_response.encode("utf-8"), signature, message_hash)
            con_message_bytes = pickle.dumps(con_message)
            conn.send(con_message_bytes)

    threading.Thread(target=receive_message, args=(client_ed_public_key,), daemon=True).start()
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
