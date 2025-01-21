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
from crypt import EcdhAes, Curve25519Sm4, Ed25519, Hasher



# 存储每个IP的最后一次发送时间
last_sent = defaultdict(lambda: 0)
SEND_INTERVAL = 0.2



def send_message(client_socket, ea_shared_key, cs_shared_key):
    try:
        cs = Curve25519Sm4()
        ed = Ed25519()
        hs = Hasher()
        while True:
            try:
                message = input("客户端: ")
                if message.lower() == 'exit':
                    break

                # 加密消息
                try:
                    ea = EcdhAes()
                    encrypted_message = ea.encrypt_data(ea_shared_key, message)
                    encrypted_message = cs.encrypt_ecb(cs_shared_key, encrypted_message)
                except Exception as e:
                    print(f"消息加密失败: {e}")
                    continue

                # 签名消息
                try:
                    signature = ed.sign_message(message.encode("utf-8"))
                except Exception as e:
                    print(f"消息签名失败: {e}")
                    continue

                # 计算消息哈希
                try:
                    message_hash = hs.ab33_hash(message)
                except Exception as e:
                    print(f"计算消息哈希失败: {e}")
                    continue

                # 打包消息
                con_message = (encrypted_message.encode("utf-8"), signature, message_hash.encode("utf-8"))
                con_message_bytes = pickle.dumps(con_message)

                # 发送消息
                try:
                    client_socket.send(con_message_bytes)
                except (ConnectionResetError, BrokenPipeError) as e:
                    print(f"发送消息失败: 连接重置或断开: {e}")
                    client_socket.close()
                    break
                except Exception as e:
                    print(f"发送消息时发生错误: {e}")
                    break

            except Exception as e:
                print(f"发送消息时发生未知错误: {e}")
                break

    except ConnectionResetError:
        print("服务器重置连接.")
        client_socket.close()
    except (socket.error, BrokenPipeError) as e:
        print(f"与服务器的连接出错: {e}")
        client_socket.close()
    except Exception as e:
        print(f"客户端发送消息时发生错误: {e}")
        client_socket.close()


def receive_message(client_socket, ea_shared_key, cs_shared_key, server_ed_public_key):
    try:
        cs = Curve25519Sm4()
        ed = Ed25519()
        hs = Hasher()
        while True:
            try:
                # 接收并反序列化数据
                try:
                    response = pickle.loads(client_socket.recv(1024))
                except pickle.UnpicklingError:
                    print("接收数据格式错误，无法反序列化")
                    continue
                except Exception as e:
                    print(f"接收数据时发生错误: {e}")
                    break

                encrypted_message = response[0]
                signature = response[1]
                message_hash = response[2]

                if not encrypted_message:
                    print("服务器暂时无响应")
                    continue

                # 解密消息
                try:
                    ea = EcdhAes()
                    decrypted_message = cs.decrypt_ecb(cs_shared_key, encrypted_message)
                    decrypted_message = ea.decrypt_data(ea_shared_key, decrypted_message)
                except Exception as e:
                    print(f"解密消息失败: {e}")
                    continue

                print("\n服务端未经检查: ", decrypted_message)

                '''
                data = "127.0.0.1"
                salt = "CN.Guangdong.Yunfu.Cheetah"
                sugar = "Zhou Cilent, Chraypt"
                '''

                # 验证消息签名
                try:
                    if ed.verify_signature(signature, decrypted_message.encode("utf-8"), server_ed_public_key):
                        # 验证消息哈希
                        if hs.ab33_hash(decrypted_message) != message_hash:
                            print(f"\n服务端: {decrypted_message}", datetime.now())
                        else:
                            print("服务端消息似乎不完整.")
                    else:
                        print("服务端消息签名验证失败.")
                except Exception as e:
                    print(f"签名验证失败: {e}")
            except ConnectionResetError:
                print("服务器重置连接.")
                break
            except Exception as e:
                print(f"接收消息时发生未知错误: {e}")
                break
    except Exception as e:
        print(f"客户端接收消息时发生错误: {e}")


def start_client():
    try:
        current_time = time.time()
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # 输入服务器信息
        server_ip = input("请输入服务器IP地址: ")
        port = int(input("请输入服务器端口号: "))

        try:
            # 连接到服务器
            client_socket.connect((server_ip, port))
        except socket.error as e:
            print(f"连接服务器失败: {e}")
            return

        try:
            # SSL 包装客户端套接字
            context = ssl.create_default_context()
            context.check_hostname = False  # 禁用主机名检查
            context.verify_mode = ssl.CERT_NONE  # 禁用证书验证
            client_socket = context.wrap_socket(client_socket, server_hostname=server_ip)
        except ssl.SSLError as e:
            print(f"SSL握手失败: {e}")
            client_socket.close()
            return

        # 检查发送频率
        if current_time - last_sent.get(server_ip, 0) < SEND_INTERVAL:
            print(f"发送频率过快，拒绝请求: {server_ip}")
            client_socket.close()
            return

        # 更新最后发送时间
        last_sent[server_ip] = int(current_time)

        # 身份验证
        print("该服务器需要验证你的身份：")
        key = input("请输入密钥: ")
        salt = input("请输入盐: ")
        sugar = input("请输入糖: ")

        try:
            hasher = Hasher()
            hashed_key = hasher.double_hash(key, salt, sugar)
        except Exception as e:
            print(f"生成哈希密钥时发生错误: {e}")
            client_socket.close()
            return

        try:
            # 发送哈希后的密钥
            client_socket.send(hashed_key.encode('utf-8'))
        except socket.error as e:
            print(f"发送哈希密钥时发生错误: {e}")
            client_socket.close()
            return

        try:
            ea = EcdhAes()
            # 创建客户端的 EA 密钥对
            client_private_key, client_public_key = ea.generate_ecc_keypair()

            # 创建客户端的 CS 密钥对
            cilent_cs = Curve25519Sm4()
            client_cs_private_key, client_cs_public_key = cilent_cs.get_private_key(), cilent_cs.get_public_key()

            # 创建客户端 EdDSA 密钥对
            ed = Ed25519()
            private_ed_key, public_ed_key = ed.serialize_private_key(), ed.serialize_public_key()

            # 发送客户端EA公钥、CS公钥和EdDSA公钥
            client_socket.send(client_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
            client_socket.send(client_cs_public_key)  # 直接发送字节数据
            client_socket.send(public_ed_key)
        except Exception as e:
            print(f"生成或发送公钥时发生错误: {e}")
            client_socket.close()
            return

        try:
            # 接收服务器公钥
            server_public_key_data = client_socket.recv(1024)
            server_public_key = serialization.load_pem_public_key(server_public_key_data)

            # 接收服务器的CS和EdDSA公钥
            server_cs_public_key = client_socket.recv(1024)
            server_ed_public_key = client_socket.recv(1024)
        except socket.error as e:
            print(f"接收公钥时发生错误: {e}")
            client_socket.close()
            return
        except Exception as e:
            print(f"解析公钥时发生错误: {e}")
            client_socket.close()
            return

        try:
            ea = EcdhAes()
            # 计算共享EA密钥和CS密钥
            client_shared_ea_key = ea.generate_shared_key(client_private_key, server_public_key)
            client_shared_cs_key = cilent_cs.generate_shared_key(server_cs_public_key).hex()
        except Exception as e:
            print(f"计算共享密钥时发生错误: {e}")
            client_socket.close()
            return

        # 启动线程处理发送和接收消息
        try:
            threading.Thread(target=send_message, args=(client_socket, client_shared_ea_key, client_shared_cs_key), daemon=True).start()
            threading.Thread(target=receive_message, args=(client_socket, client_shared_ea_key, client_shared_cs_key, server_ed_public_key), daemon=True).start()
        except Exception as e:
            print(f"启动线程时发生错误: {e}")
            client_socket.close()
            return

        while True:
            pass  # 保持主线程运行

    except Exception as e:
        print(f"客户端启动时发生未知错误: {e}")



if __name__ == "__main__":
    try:
        start_client()
    except Exception as e:
        print(f"ERROR: {e}")
