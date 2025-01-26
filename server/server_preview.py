# -*- coding: utf-8 -*-
import multiprocessing
import secrets
import ssl
import sys
import time
import pickle
import socket
import threading
import subprocess
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from cryptography.hazmat.primitives import serialization
from crypt import EcdhAes, Curve25519Sm4, Ed25519, Hasher

# 存储哈希值
HASH = '''670419071f13552cb2cf41fee37e8245d59d2073c0f015e6ac4df4a3f6233dd6cf543bf1cc838c484ee1cb7759445f4a0e55cb45f460bff6caca7f01'''

# 存储每个 IP 的连接数
connection_count = defaultdict(int)
MAX_CONNECTIONS = 10

# 存储每个 IP 的最后一次发送时间
last_sent = defaultdict(lambda: 0)
SEND_INTERVAL = 0.2

# 存储 PS 命令
PS_COMMAND = 'Stop-Process -Id (Get-NetTCPConnection -LocalPort 52000).OwningProcess'
PWSH_PATH = "C:/Program Files/PowerShell/7/pwsh.exe"

# 存储当前目录
CURRENT_DIR = Path(__file__).parent

# 检查是否是 Windows 系统
if sys.platform == 'win32':
    # 先关闭占用 52000 端口的进程
    result = subprocess.run([PWSH_PATH, 'powershell', '-Command', PS_COMMAND], capture_output=True, text=True)
else:
    print("请注意先关闭初始端口——52000")



class Server:
    def __init__(self):
        self.anon_port = None
        self.server_cs_shared_key = None
        self.server_ea_shared_key = None
        self.client_ed_public_key = None
        self.server_ea_private_key = None
        self.server_cs_private_key = None
        self.exchange_port = None

    @staticmethod
    def ddos_check(conn, addr):
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

        # 检查发送频率
        if current_time - last_sent[addr[0]] < SEND_INTERVAL:
            print(f"发送频率过快，拒绝请求: {addr}")
            conn.close()
            return

        # 更新最后一次发送时间
        last_sent[addr[0]] = int(current_time)

    @staticmethod
    def init_crypt():
        cs = Curve25519Sm4()
        ed = Ed25519()
        hs = Hasher()
        ea = EcdhAes()
        return cs, ed, hs, ea

    def handle_init(self, conn, addr):
        # 使用基本的 DDoS 检查
        self.ddos_check(conn, addr)

        try:
            while True:
                # 随机生成一个 49152-65535 的整数
                self.exchange_port = secrets.randbelow(65535 - 49152 + 1) + 49152
                if self.exchange_port != 52000:
                    # 检查端口是否被占用
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        try:
                            s.bind(('localhost', self.exchange_port))
                            try:
                                # 发送交换端口
                                conn.send(str(self.exchange_port).encode())
                                break
                            except Exception as e:
                                print(f"发送端口时出错: {e}")
                                break
                        except socket.error:
                            continue
                else:
                    continue
        except Exception as e:
            print(f"生成密钥交换端口时出错: {e}")

    def start_init_server(self):
        try:
            # 创建一个 TCP/IP socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.bind(('0.0.0.0', 52000))
            server_socket.listen(1)
            print(f"监听初始端口...")

            # 拼接相对路径
            certfile = CURRENT_DIR / 'pems' / 'certfile.crt'
            keyfile = CURRENT_DIR / 'pems' / 'keyfile.key'

            # 创建 SSL 上下文
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=certfile,
                                    keyfile=keyfile)

            # 包装Socket为SSL连接
            server_socket = context.wrap_socket(server_socket, server_side=True)

            while True:
                try:
                    # 接受客户端连接
                    conn, addr = server_socket.accept()
                    print(f"建立连接: {addr}")

                    # 创建新线程处理客户端连接
                    threading.Thread(target=self.handle_init, args=(conn, addr), daemon=True).start()

                except ssl.SSLError as e:
                    print(f"初始连接SSL 错误: {e}")
                    continue  # 继续监听新连接，不退出程序

                except socket.error as e:
                    print(f"Socket 错误: {e}")
                    continue  # 继续监听新连接，不退出程序

                except Exception as e:
                        print(f"初始端口出错: {e}")
                        break
        except OSError as e:
            print(f"服务端启动失败，系统错误：{e}")
        except Exception as e:
            print(f"服务端启动失败，未知错误：{e}")
        finally:
            print("服务端程序即将宕机")
            if 'server_socket' in locals():
                sys.exit()
            sys.exit()

    def handle_exchange(self, conn, addr):
        self.ddos_check(conn, addr)
        cs, ed, hs, ea = self.init_crypt()

        # 生成服务器密钥对
        self.server_ea_private_key, server_ea_public_key = ea.generate_ecc_keypair()
        self.server_cs_private_key, server_cs_public_key = cs.get_private_key(), cs.get_public_key()
        server_ed_private_key, server_ed_public_key = ed.serialize_private_key(), ed.serialize_public_key()

        # 发送服务器的公钥给客户端
        try:
            conn.send(server_ea_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
            conn.send(server_cs_public_key)
            conn.send(server_ed_public_key)
        except Exception as e:
            print(f"发送公钥时出错: {e}")
            conn.close()
            return

        # 接收客户端的公钥
        try:
            client_ea_public_key = serialization.load_pem_public_key(conn.recv(1024))
            client_cs_public_key = conn.recv(1024)
            self.client_ed_public_key = conn.recv(1024)
        except Exception as e:
            print(f"接收客户端公钥时出错: {e}")
            conn.close()
            return None

        # 计算共享密钥
        try:
            self.server_ea_shared_key = ea.generate_shared_key(self.server_ea_private_key, client_ea_public_key).hex()
            self.server_cs_shared_key = cs.generate_shared_key(client_cs_public_key).hex()
        except Exception as e:
            print(f"计算共享密钥时出错: {e}")
            conn.close()
            return None

        try:
            while True:
                # 随机生成一个 49152-65535 的整数
                self.anon_port = secrets.randbelow(65535 - 49152 + 1) + 49152
                if self.anon_port != 52000 and self.anon_port != self.exchange_port:
                    # 检查端口是否被占用
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        try:
                            s.bind(('localhost', self.anon_port))
                            try:
                                encrypted_anon_port = ea.encrypt_data(self.server_ea_shared_key, str(self.anon_port))
                                encrypted_anon_port = cs.encrypt_ecb(self.server_cs_shared_key, encrypted_anon_port)
                                signature = ed.sign_message(str(self.anon_port).encode('utf-8'))
                                con_message = (encrypted_anon_port.encode('utf-8'), signature)
                                con_message_bytes = pickle.dumps(con_message)
                                conn.send(con_message_bytes)
                                break
                            except Exception as e:
                                print(f"保存端口跃迁点时出错: {e}")
                                break
                        except socket.error:
                            continue
                else:
                    continue
        except Exception as e:
            print(f"生成端口跃迁点时出错: {e}")

    def start_exchange_server(self):
        try:
            # 等待直到 self.exchange_port 不为 None
            while self.exchange_port is None:
                print("等待 exchange_port 被设置...")
                time.sleep(1)

            print("交换端口被设置！")

            # 创建一个 TCP/IP socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.bind(('0.0.0.0', self.exchange_port))
            server_socket.listen(1)
            print(f"监听交换端口...")

            # 拼接相对路径
            certfile = CURRENT_DIR / 'pems' / 'certfile.crt'
            keyfile = CURRENT_DIR / 'pems' / 'keyfile.key'

            # 创建 SSL 上下文
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=certfile,
                                    keyfile=keyfile)

            # 包装Socket为SSL连接
            server_socket = context.wrap_socket(server_socket, server_side=True)

            while True:
                try:
                    # 接受客户端连接
                    conn, addr = server_socket.accept()
                    print(f"建立连接: {addr}")

                    # 创建新线程处理客户端连接
                    threading.Thread(target=self.handle_exchange, args=(conn, addr), daemon=True).start()

                except ssl.SSLError as e:
                    print(f"交换连接SSL 错误: {e}")
                    continue  # 继续监听新连接，不退出程序

                except socket.error as e:
                    print(f"Socket 错误: {e}")
                    continue  # 继续监听新连接，不退出程序

                except Exception as e:
                        print(f"初始端口出错: {e}")
                        break
        except OSError as e:
            print(f"服务端启动失败，系统错误：{e}")
        except Exception as e:
            print(f"服务端启动失败，未知错误：{e}")
        finally:
            print("服务器即将宕机")
            sys.exit()

    def handle_anon(self, conn, addr):
        self.ddos_check(conn, addr)
        cs, ed, hs, ea = self.init_crypt()

        try:
            hashed_key = conn.recv(1024).decode('utf-8')
            if hashed_key != HASH:
                print("密钥验证失败")
                conn.close()
                return
            print("密钥验证成功")

            def receive_message():
                while True:
                    try:
                        data = pickle.loads(conn.recv(1024))
                        encrypted_message = data[0]
                        signature = data[1]
                        message_hash = data[2]
                        if not encrypted_message:
                            print("客户端断开连接.")
                            break
                        decrypted_data = cs.decrypt_ecb(self.server_cs_private_key, encrypted_message)
                        decrypted_data = ea.decrypt_data(self.server_ea_private_key, decrypted_data)
                        print("\n客户端未经检查: ", decrypted_data)

                        if ed.verify_signature(signature, decrypted_data.encode('utf-8'), self.client_ed_public_key):
                            if hs.ab33_hash(decrypted_data) == message_hash:
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
                    while True:
                        try:
                            response = input("服务端: ")
                            if response.lower() == 'exit':
                                break
                            encrypted_response = ea.encrypt_data(self.server_ea_shared_key, response)
                            encrypted_response = cs.encrypt_ecb(self.server_cs_shared_key, encrypted_response)
                            signature = ed.sign_message(response.encode('utf-8'))
                            message_hash = hs.ab33_hash(response)
                            con_message = (encrypted_response.encode('utf-8'), signature, message_hash)
                            con_message_bytes = pickle.dumps(con_message)
                            conn.send(con_message_bytes)
                        except Exception as e:
                            print(f"加密和发送消息时出错: {e}")
                            continue
                # 启动接收和发送消息的线程
                threading.Thread(target=receive_message, args=(self.client_ed_public_key,), daemon=True).start()
                threading.Thread(target=send_message, daemon=True).start()

                while True:
                    pass

        except Exception as e:
            print(f"处理客户端出错: {e}")
        finally:
            try:
                conn.close()
            except Exception as e:
                print(f"关闭连接出错: {e}")
                sys.exit()

    def start_anon_server(self):
        try:
            # 等待直到 self.anon_port 不为 None
            while self.anon_port is None:
                print("等待 anon_port 被设置...")
                time.sleep(1)

            print("匿名端口被设置！")

            # 创建一个 TCP/IP socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.bind(('0.0.0.0', self.anon_port))
            server_socket.listen(1)
            print(f"监听匿名端口...")

            # 获取当前文件路径
            current_path = Path(__file__).parent

            # 拼接相对路径
            certfile = current_path / 'pems' / 'certfile.crt'
            keyfile = current_path / 'pems' / 'keyfile.key'

            # 创建 SSL 上下文
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=certfile,
                                    keyfile=keyfile)

            # 包装Socket为SSL连接
            server_socket = context.wrap_socket(server_socket, server_side=True)

            while True:
                try:
                    # 接受客户端连接
                    conn, addr = server_socket.accept()
                    print(f"建立连接: {addr}")

                    # 创建新线程处理客户端连接
                    threading.Thread(target=self.handle_anon, args=(conn, addr), daemon=True).start()

                except ssl.SSLError as e:
                    print(f"端口跃迁SSL 错误: {e}")
                    continue  # 继续监听新连接，不退出程序

                except socket.error as e:
                    print(f"Socket 错误: {e}")
                    continue  # 继续监听新连接，不退出程序

                except Exception as e:
                        print(f"初始端口出错: {e}")
                        break
        except OSError as e:
            print(f"服务端启动失败，系统错误：{e}")
        except Exception as e:
            print(f"服务端启动失败，未知错误：{e}")
        finally:
            print("服务端程序即将宕机")
            sys.exit()

if __name__ == '__main__':
    try:
        server = Server()
        threading.Thread(target=server.start_init_server, daemon=True).start()
        threading.Thread(target=server.start_exchange_server, daemon=True).start()
        threading.Thread(target=server.start_anon_server, daemon=True).start()

        while True:
            pass

    except Exception as e:
        print(f"服务端启动失败，未知错误：{e}")

