import sys
import ssl
import time
import pickle
import socket
import threading
import subprocess
sys.path.append("/crypt.py")
from datetime import datetime
from collections import defaultdict
from cryptography.hazmat.primitives import serialization
from crypt import EcdhAesCrypt, Curve25519Sm4, Ed25519, Hasher



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

import time
import threading
import pickle
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.exceptions import InvalidSignature


def handle_client(conn, addr):
    try:
        current_time = time.time()
        # 检查当前IP的连接数
        if connection_count[addr[0]] >= MAX_CONNECTIONS:
            print(f"连接数超过限制，拒绝连接: {addr}")
            conn.close()
            return

        # 增加连接数
        connection_count[addr[0]] += 1
        print(f"建立连接: {addr}")
        conn.settimeout(600)

        if current_time - last_sent[addr[0]] < SEND_INTERVAL:
            print(f"发送频率过快，拒绝请求: {addr}")
            conn.close()
            return

        # 更新最后一次发送时间
        last_sent[addr[0]] = int(current_time)

        # 接收客户端的哈希后的密钥
        hashed_key = conn.recv(1024).decode('utf-8')
        if hashed_key != HASH:
            print("密钥验证失败")
            conn.close()
            return
        print("密钥验证成功")

        # 生成服务器的密钥对
        server_private_key, server_public_key = EcdhAesCrypt.generate_ecc_keypair()
        server_cs = Curve25519Sm4()
        server_cs_private_key, server_cs_public_key = server_cs.get_private_key(), server_cs.get_public_key()
        ed = Ed25519()
        private_ed_key, public_ed_key = ed.serialize_private_key(), ed.serialize_public_key()

        # 发送公钥给客户端
        try:
            conn.send(server_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
            conn.send(server_cs_public_key)
            conn.send(public_ed_key)
        except Exception as e:
            print(f"发送公钥时出错: {e}")
            conn.close()
            return

        # 接收客户端的公钥
        try:
            client_public_key_data = conn.recv(1024)
            client_public_key = serialization.load_pem_public_key(client_public_key_data)
            client_cs_public_key = conn.recv(1024)
            client_ed_public_key = conn.recv(1024)
        except Exception as e:
            print(f"接收客户端公钥时出错: {e}")
            conn.close()
            return

        # 计算共享密钥
        try:
            server_shared_key = EcdhAesCrypt.generate_shared_key(server_private_key, client_public_key)
            server_cs_shared_key = server_cs.generate_shared_key(client_cs_public_key).hex()
        except Exception as e:
            print(f"计算共享密钥时出错: {e}")
            conn.close()
            return

        def receive_message(client_ed_public_key):
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
                    print("\n客户端未经检查: ", decrypted_data)

                    if ed.verify_signature(signature, decrypted_data.encode("utf-8"), client_ed_public_key):
                        if hs.ab33_hash(decrypted_data) != message_hash:
                            print(f"\n客户端: {decrypted_data}", datetime.now())
                        else:
                            print("客户端消息似乎不完整.")
                    else:
                        print("客户端消息签名验证失败.")
                except ConnectionResetError:
                    print("客户端重置连接.")
                    break
                except Exception as e:
                    print(f"接收消息时出错: {e}")
                    break

        def send_message():
            cs = Curve25519Sm4()
            ed = Ed25519()
            hs = Hasher()
            while True:
                try:
                    response = input("服务端: ")
                    if response.lower() == 'exit':
                        break
                    encrypted_response = EcdhAesCrypt.encrypt_data(server_shared_key, response)
                    encrypted_response = cs.encrypt_ecb(server_cs_shared_key, encrypted_response)
                    signature = ed.sign_message(response.encode("utf-8"))
                    message_hash = hs.ab33_hash(response)
                    con_message = (encrypted_response.encode("utf-8"), signature, message_hash)
                    con_message_bytes = pickle.dumps(con_message)
                    conn.send(con_message_bytes)
                except Exception as e:
                    print(f"发送消息时出错: {e}")
                    break

        # 启动接收和发送消息的线程
        threading.Thread(target=receive_message, args=(client_ed_public_key,), daemon=True).start()
        threading.Thread(target=send_message, daemon=True).start()

        while True:
            pass

    except Exception as e:
        print(f"处理客户端时出错: {e}")
    finally:
        # 确保连接关闭
        try:
            conn.close()
        except Exception as e:
            print(f"关闭连接时出错: {e}")


def start_server():
    try:
        # 创建服务器Socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('0.0.0.0', 52000))  # 绑定到所有IP地址上的 52000 端口
        server_socket.listen(1)  # 开始监听
        print("服务端在端口 52000 监听...")

        # 创建SSL上下文
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile="D:/chraypt/server/pems/certfile.crt",
                                keyfile="D:/chraypt/server/pems/keyfile.key")

        # 包装Socket为SSL连接
        server_socket = context.wrap_socket(server_socket, server_side=True)

        while True:
            try:
                # 接受客户端连接
                conn, addr = server_socket.accept()
                print(f"建立连接: {addr}")

                # 创建新线程处理客户端连接
                threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

            except ssl.SSLError as e:
                print(f"SSL 错误: {e}")
                continue  # 继续监听新连接，不退出程序

            except socket.error as e:
                print(f"Socket 错误: {e}")
                continue  # 继续监听新连接，不退出程序

            except Exception as e:
                print(f"发生错误: {e}")
                break  # 如果发生其他异常，退出监听

    except OSError as e:
        print(f"服务器启动失败，系统错误: {e}")
    except Exception as e:
        print(f"服务端运行时发生未知错误: {e}")
    finally:
        if 'server_socket' in locals():
            conn.close()  # 确保关闭Socket
        print("服务器已关闭.")



if __name__ == "__main__":
    try:
        start_server()
    except Exception as e:
        print(f"ERROR: {e}")
