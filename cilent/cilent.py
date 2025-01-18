import socket  # 导入 socket 库，提供网络通信功能
import ssl  # 导入 ssl 库，提供 SSL 加密支持
import threading  # 导入 threading 库，支持多线程处理
import hashlib  # 导入 hashlib 库，提供哈希算法支持
from datetime import datetime  # 导入 datetime 库，提供当前时间的获取功能

# 定义一个密钥，通常用于加密或认证
key = ''''
viGtdaBMJ.CfdbM34FCDKmwT;0kX!l%/chtcpGt,/pI:\iR!Tl"jmUFh/56)7yI3A0+V=.8R164(NTidV}y9HLLuSdEEw318|LkPw$t]y**<'0~ol+[y6}(T,,nInF*){*D]l'Gn;Xj0.oTCg6qaL*U>xw"cV(h$Vre$0jcmH7NH)qys!J}kmX45F|!)X}NrS+G@7?|&$}v\-KlfSm1g>od^g+3Z0582N:x?;l\vT@@3'JI?:Y~Fjn5h[\[?^Bt<*C0_&r]t-,N9DBeuTu$:!wE4p/qr4)!gqmkBF03]3LuKuUW2a,7VAm+NCcLpmre(HB@pP8$}3!yOeIZ^U{&~L5X5CIdtv#L%JJ-PLkXABHLwt#3@9L[dw2,qmC,j1PIL7M!j/:sO_W!48FvkjNrdBA^=]LJZB"XX<c]O1Nw<JDjqZsxz\]D^+od+z0#ADF*"V'CX-!=#2rxC}1]n)s3Im/Q(V[1nIjK1#$M+B(M4{8KBg^k4V=>nAsk+sD\
'''.encode('utf-8')  # 将密钥转换为 UTF-8 编码格式

# 定义一个双重哈希的函数
def double_hash(data):
    """使用 SHA3-512 和 SHA2-512 进行双重哈希"""
    # 先使用 SHA2-512 哈希
    sha2_hash = hashlib.sha512(data).digest()  # 使用 SHA2-512 计算哈希值并返回二进制数据
    # 然后将 SHA2-512 的输出再次使用 SHA3-512 哈希
    sha3_hash = hashlib.sha3_512(sha2_hash).hexdigest()  # 使用 SHA3-512 对上一步结果进行哈希并返回十六进制字符串
    return sha3_hash  # 返回最终的哈希值

# 发送消息的函数
def send_message(client_socket):
    while True:
        message = input("客户端: ")  # 获取用户输入的消息
        if message.lower() == 'exit':  # 如果输入是 'exit'，则退出
            break
        client_socket.send(message.encode('utf-8'))  # 将消息编码为 UTF-8 并发送到服务器

# 接收消息的函数
def receive_message(client_socket):
    while True:
        response = client_socket.recv(1024).decode('utf-8')  # 接收最大 1024 字节的数据并解码为 UTF-8
        print(f"\n服务器: {response}", datetime.now())  # 打印接收到的消息和当前时间

# 启动客户端的函数
def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 创建一个 TCP/IP 套接字
    server_ip = input("输入服务端的 IP 地址: ")  # 输入服务器的 IP 地址
    client_socket.connect((server_ip, 12345))  # 连接到服务器指定的 IP 地址和端口 12345

    # 使用 SSL 加密套接字
    client_socket = ssl.wrap_socket(client_socket, keyfile=None, certfile=None, server_side=False)

    print(f"连接到服务器：{server_ip}.")  # 输出连接信息

    # 计算 key 的哈希值并发送给服务器
    client_hash = double_hash(key)  # 计算密钥的双重哈希值
    client_socket.send(client_hash.encode('utf-8'))  # 将哈希值编码并发送到服务器
    print(f"发送哈希值: {client_hash}")  # 打印发送的哈希值

    # 启动两个线程，分别处理发送消息和接收消息
    threading.Thread(target=send_message, args=(client_socket,), daemon=True).start()  # 创建并启动发送消息的线程
    threading.Thread(target=receive_message, args=(client_socket,), daemon=True).start()  # 创建并启动接收消息的线程

    while True:
        pass  # 保持主线程运行，等待线程完成

# 主程序入口
if __name__ == "__main__":
    try:
        start_client()  # 启动客户端
    except Exception as e:  # 捕获异常并打印错误信息
        print(f"ERROR: {e}")
