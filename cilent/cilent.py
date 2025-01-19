import sys
import ssl
import time
import pickle
import socket
import threading
sys.path.append("/crypt.py")
from datetime import datetime
from collections import defaultdict
from cryptography.hazmat.primitives import serialization
from crypt import EcdhAesCrypt, Curve25519Sm4, Ed25519, Hasher



# 存储每个IP的最后一次发送时间
last_sent = defaultdict(lambda: 0)
SEND_INTERVAL = 0.2



def send_message(client_socket, ea_shared_key, cs_shared_key):
    cs = Curve25519Sm4()
    ed = Ed25519()
    hs = Hasher()
    while True:
        message = input("客户端: ")
        if message.lower() == 'exit':
            break
        encrypted_message = EcdhAesCrypt.encrypt_data(ea_shared_key, message)
        encrypted_message = cs.encrypt_ecb(cs_shared_key, encrypted_message)
        signature = ed.sign_message(message.encode("utf-8"))
        message_hash = hs.ab33_hash(message)
        con_message = (encrypted_message.encode("utf-8"), signature, message_hash.encode("utf-8"))
        con_message_bytes = pickle.dumps(con_message)
        client_socket.send(con_message_bytes)


def receive_message(client_socket, ea_shared_key, cs_shared_key,server_ed_public_key):
    cs = Curve25519Sm4()
    ed = Ed25519()
    hs = Hasher()
    while True:
        try:
            response = pickle.loads(client_socket.recv(1024))
            encrypted_message = response[0]
            signature = response[1]
            message_hash = response[2]
            if not encrypted_message:
                print("服务器暂时无响应")
                continue
            decrypted_message = cs.decrypt_ecb(cs_shared_key, encrypted_message)
            decrypted_message = EcdhAesCrypt.decrypt_data(ea_shared_key, decrypted_message)
            print("\n客户端未经检查: ",decrypted_message)
            if ed.verify_signature(signature, decrypted_message.encode("utf-8"),server_ed_public_key):
                if hs.ab33_hash(decrypted_message) != message_hash:
                 print(f"\n客户端: {decrypted_message}", datetime.now())
                else:
                    print("客户端消息似乎不完整.")
            else:
                print("客户端消息签名验证失败.")
        except ConnectionResetError:
            print("服务器重置连接.")
            break


def start_client():
    current_time = time.time()
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_ip =input("请输入服务器IP地址: ")

    client_socket.connect((server_ip, 52000))
    context = ssl.create_default_context()
    context.check_hostname = False  # 禁用主机名检查
    context.verify_mode = ssl.CERT_NONE  # 禁用证书验证
    client_socket = context.wrap_socket(client_socket, server_hostname=server_ip)

    if current_time - last_sent[server_ip[0]] < SEND_INTERVAL:
        print(f"发送频率过快，拒绝请求: {server_ip}")
        client_socket.close()
        return

    # 更新最后一次发送时间
    last_sent[server_ip[0]] =int(current_time)


    '''
    data = "127.0.0.1"
    salt = "CN.Guangdong.Yunfu.Cheetah"
    sugar = "Zhou Cilent, Chraypt"
    '''

    # 验证身份
    print("该服务器需要验证你的身份：")
    key = input("请输入密钥: ")
    salt = input("请输入盐: ")
    sugar = input("请输入糖: ")
    hasher = Hasher()
    hashed_key = hasher.double_hash(key, salt, sugar)

    # 发送哈希后的密钥
    client_socket.send(hashed_key.encode('utf-8'))

    # 创建客户端的 EA 密钥对
    client_private_key, client_public_key = EcdhAesCrypt.generate_ecc_keypair()

    # 创建客户端的 CS 密钥对
    cilent_cs = Curve25519Sm4()
    client_cs_private_key, client_cs_public_key = cilent_cs.get_private_key(), cilent_cs.get_public_key()

    # 创建客户端 EdDSA 密钥对
    ed = Ed25519()
    private_ed_key, public_ed_key = ed.serialize_private_key(), ed.serialize_public_key()

    # 发送客户端EA公钥
    client_socket.send(client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

    # 发送客户端CS公钥
    client_socket.send(client_cs_public_key)  # 直接发送字节数据

    # 发送客户端EdDSA公钥
    client_socket.send(public_ed_key)

    # 接收服务器的EA公钥
    server_public_key_data = client_socket.recv(1024)
    server_public_key = serialization.load_pem_public_key(server_public_key_data)

    # 接收服务器的CS公钥
    server_cs_public_key = client_socket.recv(1024)

    # 接收服务器的EdDSA公钥
    server_ed_public_key = client_socket.recv(1024)

    # 计算共享EA密钥
    client_shared_ea_key = EcdhAesCrypt.generate_shared_key(client_private_key, server_public_key)

    # 计算共享CS密钥
    client_shared_cs_key = cilent_cs.generate_shared_key(server_cs_public_key).hex()

    # 启动两个线程分别处理发送和接收
    threading.Thread(target=send_message, args=(client_socket, client_shared_ea_key, client_shared_cs_key), daemon=True).start()
    threading.Thread(target=receive_message, args=(client_socket, client_shared_ea_key, client_shared_cs_key, server_ed_public_key), daemon=True).start()

    while True:
        pass  # 保持主线程运行



if __name__ == "__main__":
    try:
        start_client()
    except Exception as e:
        print(f"ERROR: {e}")
