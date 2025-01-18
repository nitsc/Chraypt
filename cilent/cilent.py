import socket
import ssl
import threading
import hashlib
from datetime import datetime

key = ''''
viGtdaBMJ.CfdbM34FCDKmwT;0kX!l%/chtcpGt,/pI:\iR!Tl"jmUFh/56)7yI3A0+V=.8R164(NTidV}y9HLLuSdEEw318|LkPw$t]y**<'0~ol+[y6}(T,,nInF*){*D]l'Gn;Xj0.oTCg6qaL*U>xw"cV(h$Vre$0jcmH7NH)qys!J}kmX45F|!)X}NrS+G@7?|&$}v\-KlfSm1g>od^g+3Z0582N:x?;l\vT@@3'JI?:Y~Fjn5h[\[?^Bt<*C0_&r]t-,N9DBeuTu$:!wE4p/qr4)!gqmkBF03]3LuKuUW2a,7VAm+NCcLpmre(HB@pP8$}3!yOeIZ^U{&~L5X5CIdtv#L%JJ-PLkXABHLwt#3@9L[dw2,qmC,j1PIL7M!j/:sO_W!48FvkjNrdBA^=]LJZB"XX<c]O1Nw<JDjqZsxz\]D^+od+z0#ADF*"V'CX-!=#2rxC}1]n)s3Im/Q(V[1nIjK1#$M+B(M4{8KBg^k4V=>nAsk+sD\
'''.encode('utf-8')

def double_hash(data):
    """使用 SHA3-512 和 SHA2-512 进行双重哈希"""
    # 先使用 SHA2-512 哈希
    sha2_hash = hashlib.sha512(data).digest()
    # 然后将 SHA2-512 的输出再次使用 SHA3-512 哈希
    sha3_hash = hashlib.sha3_512(sha2_hash).hexdigest()
    return sha3_hash

def send_message(client_socket):
    while True:
        message = input("客户端: ")
        if message.lower() == 'exit':
            break
        client_socket.send(message.encode('utf-8'))

def receive_message(client_socket):
    while True:
        response = client_socket.recv(1024).decode('utf-8')
        print(f"\n服务器: {response}", datetime.now())

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_ip = input("输入服务端的 IP 地址: ")  # 输入服务端的 IP 地址
    client_socket.connect((server_ip, 12345))  # 连接到指定的 IP 地址和端口

    # 使用 SSL 套接字
    client_socket = ssl.wrap_socket(client_socket, keyfile=None, certfile=None, server_side=False)

    print(f"连接到服务器：{server_ip}.")

    # 计算 key 的哈希值并发送给服务端
    client_hash = double_hash(key)
    client_socket.send(client_hash.encode('utf-8'))
    print(f"发送哈希值: {client_hash}")

    # 启动两个线程分别处理发送和接收
    threading.Thread(target=send_message, args=(client_socket,), daemon=True).start()
    threading.Thread(target=receive_message, args=(client_socket,), daemon=True).start()

    while True:
        pass  # 保持主线程运行

if __name__ == "__main__":
    try:
        start_client()
    except Exception as e:
        print(f"ERROR: {e}")