# -*- coding: utf-8 -*-
import secrets
import ssl
import sys
import time
import pickle
import socket
import threading
import traceback
from datetime import datetime
from collections import defaultdict
from cryptography.hazmat.primitives import serialization
from crypt import EcdhAes, Curve25519Sm4, Ed25519, Hasher

# 存储每个IP的最后一次发送时间
last_sent = defaultdict(lambda: 0)
SEND_INTERVAL = 0.2



class Client:
    def __init__(self):
        self.exchange_port = None
        self.anon_port_data = None
        self.anon_port = None
        self.client_cs_shared_key = None
        self.client_ea_shared_key = None
        self.server_ed_public_key = None
        self.client_ea_private_key = None
        self.client_cs_private_key = None
        self.server_ip = '127.0.0.1'

    @staticmethod
    def ddos_check(client_socket, server_ip):
        current_time = time.time()
        if current_time - last_sent.get(server_ip, 0) < SEND_INTERVAL:
            print(f"发送频率过快，拒绝请求: {server_ip}")
            client_socket.close()
            return

        # 更新最后发送时间
        last_sent[server_ip] = int(current_time)

    @staticmethod
    def init_crypt():
        cs = Curve25519Sm4()
        ed = Ed25519()
        hs = Hasher()
        ea = EcdhAes()
        return cs, ed, hs, ea

    def wait(self, port_type):
        while True:
            try:
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.settimeout(1)  # 设置超时，防止一直阻塞
                if port_type == 'exchange':
                    client_socket.connect((self.server_ip, int(self.exchange_port)))
                    print(f"成功连接到交换端口")
                    return client_socket  # 连接成功，返回client_socket
                elif port_type == 'anon':
                    client_socket.connect((self.server_ip, int(self.anon_port)))
                    print("成功连接到匿名端口")
                    return client_socket  # 连接成功，返回client_socket
            except (socket.error, socket.timeout) as e:
                print(f"等待交换端口开放... {e}")
                time.sleep(3)  # 等待1秒再尝试连接

    def client_init(self):
        try:
            self.server_ip = "127.0.0.1"
            server_port = 52000

            try:
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.connect((self.server_ip, server_port))
            except socket.error as e:
                print(f"连接服务器失败：{e}")
                return None

            self.ddos_check(client_socket, self.server_ip)

            try:
                context = ssl.create_default_context()
                context.check_hostname = False  # 禁用主机名检查
                context.verify_mode = ssl.CERT_NONE  # 禁用证书验证
                client_socket = context.wrap_socket(client_socket, server_hostname=self.server_ip)
            except ssl.SSLError as e:
                print(f"SSL握手失败: {e}")
                client_socket.close()
                return None

            try:
                self.exchange_port = client_socket.recv(1024)
                return self.exchange_port
            except socket.error as e:
                print(f"接收数据失败: {e}")
                client_socket.close()
                return None
        except Exception as e:
            print(f"初始端口连接失败: {e}")

    def client_exchange(self):
        try:
            print(f"{self.server_ip}:{int(self.exchange_port)}")

            # 等待交换端口开放
            client_socket = self.wait("exchange")

            cs, ed, hs, ea = self.init_crypt()
            self.ddos_check(client_socket, self.server_ip)

            # 生成客户端密钥对
            self.client_ea_private_key, client_ea_public_key = ea.generate_ecc_keypair()
            self.client_cs_private_key, client_cs_public_key = cs.get_private_key(), cs.get_public_key()
            client_ed_private_key, client_ed_public_key = ed.serialize_private_key(), ed.serialize_public_key()

            # 发送客户端公钥给服务器
            try:
                client_socket.send(client_ea_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
                client_socket.send(client_cs_public_key)
                client_socket.send(client_ed_public_key)
            except socket.error as e:
                print(f"发送公钥失败: {e}")
                client_socket.close()
                return None

            # 接收服务器公钥
            try:
                server_ea_public_key = serialization.load_pem_public_key(client_socket.recv(1024))
                server_cs_public_key = client_socket.recv(1024)
                self.server_ed_public_key = client_socket.recv(1024)
            except socket.error as e:
                print(f"接收公钥失败: {e}")
                client_socket.close()
                return None

            # 计算共享密钥
            try:
                self.client_ea_shared_key = ea.generate_shared_key(self.client_ea_private_key, server_ea_public_key).hex()
                self.client_cs_shared_key = cs.generate_shared_key(server_cs_public_key).hex()
            except Exception as e:
                print(f"计算共享密钥失败: {e}")
                client_socket.close()
                return None

            # 接收端口跃迁点数据包
            try:
                self.anon_port_data = client_socket.recv(1024)
                try:
                    # 反序列化端口跃迁点数据包
                    self.anon_port_data = pickle.loads(self.anon_port_data)
                except pickle.UnpicklingError:
                    print("接收到的数据无法反序列化")
                    client_socket.close()
                except Exception as e:
                    print(f"未知错误: {e}")
            except Exception as e:
                print(f"接收端口跃迁点数据包失败: {e}")

            try:
                encrypted_port = self.anon_port_data[0]
                signature = self.anon_port_data[1]

                if not encrypted_port:
                    print("端口跃迁点数据包为空")
                    client_socket.close()

                # 解密
                try:
                    self.anon_port = cs.decrypt_ecb(self.client_cs_shared_key, encrypted_port)
                    self.anon_port = ea.decrypt_data(self.client_ea_shared_key, self.anon_port)
                    try:
                        if ed.verify_signature(str(signature).encode('utf-8'), self.anon_port, self.server_ed_public_key):
                            return self.anon_port
                        else:
                            print("验证签名失败")
                            return self.anon_port
                    except Exception as e:
                        print(f"验证签名失败: {e}")
                        return self.anon_port
                except Exception as e:
                    print(f"解密端口跃迁点数据包失败: {e}")
                    return None
            except Exception as e:
                print(f"提取端口跃迁点数据包失败: {e}")
                return None
        except Exception as e:
            print(f"连接到服务器交换端口失败: {e}")
            traceback.print_exc()

    def client_anon(self):
        try:
            cs, ed, hs, ea = self.init_crypt()
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.server_ip, self.anon_port))
            self.ddos_check(client_socket, self.server_ip)

            def receive_message():
                while True:
                    try:
                        data = pickle.loads(client_socket.recv(1024))
                        encrypted_data = data[0]
                        signature = data[1]
                        message_hash = data[2]

                        if not encrypted_data:
                            print("数据包为空")
                            break

                        decrpted_data = cs.decrypt_ecb(self.client_cs_private_key, encrypted_data)
                        decrpted_data = ea.decrypt_data(self.client_ea_private_key, decrpted_data)
                        print(f"\n服务端未经检查：{decrpted_data}")

                        if ed.verify_signature(signature, decrpted_data.encode('utf-8'), self.server_ed_public_key):
                            if hs.ab33_hash(decrpted_data) == message_hash:
                                print(f"\n服务端：{decrpted_data}", datetime.now())
                            else:
                                print("服务端消息不完整")
                        else:
                            print("服务端消息签名验证失败")
                    except ConnectionResetError:
                        print("服务端重置连接")
                        break
                    except Exception as e:
                        print(f"接收消息时出错: {e}")
                        break

            def send_message():
                while True:
                    try:
                        message = input("客户端：")
                        if message.lower() == "exit":
                            break
                        encrypted_message = ea.encrypt_data(self.client_ea_shared_key, message.encode('utf-8'))
                        encrypted_message = cs.encrypt_ecb(self.client_cs_shared_key, encrypted_message)
                        signature = ed.sign_message(message.encode('utf-8'))
                        message_hash = hs.ab33_hash(message).encode('utf-8')
                        con_message = (encrypted_message, signature, message_hash)
                        con_message_bytes = pickle.dumps(con_message)
                        client_socket.send(con_message_bytes)
                    except ConnectionResetError:
                        print("服务端重置连接")
                        break
                    except Exception as e:
                        print(f"加密和发送消息时出错: {e}")
                        continue

            # 启动接收和发送消息的线程
            try:
                threading.Thread(target=receive_message, daemon=True).start()
                threading.Thread(target=send_message, daemon=True).start()
            except Exception as e:
                print(f"启动线程时出错: {e}")
                client_socket.close()
                sys.exit()

            while True:
                pass

        except OSError as e:
            print(f"客户端启动失败，系统错误：{e}")
        except Exception as e:
            print(f"客户端启动失败，未知错误：{e}")
        finally:
            print("客户端程序即将宕机")
            sys.exit()

if __name__ == "__main__":
    try:
        client = Client()
        client.client_init()
        client.client_exchange()
        client.client_anon()
    except Exception as e:
        print(f"客户端启动时出错: {e}")








