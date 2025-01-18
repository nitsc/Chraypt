import socket
import threading
import ssl
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

def handle_client(conn, addr):
    print(f"建立连接: {addr}")

    # 先接收客户端的 key 哈希值
    client_hash = conn.recv(1024).decode('utf-8')
    print(f"收到客户端的哈希值: {client_hash}")

    # 验证客户端传来的哈希值
    server_hash = double_hash(key)  # 服务端计算 key 的哈希值
    if client_hash != server_hash:
        print("哈希值不匹配，拒绝连接！")
        conn.close()
        return

    print("哈希值验证通过，开始通信.")

    def receive_message():
        while True:
            try:
                data = conn.recv(1024).decode('utf-8')
                if not data:  # 客户端断开连接
                    print("客户端断开连接.")
                    break
                print(f"\n客户端: {data}", datetime.now())
            except ConnectionResetError:
                print("客户端重置连接.")
                break

    def send_message():
        while True:
            response = input("服务端: ")
            if response.lower() == 'exit':
                break
            conn.send(response.encode('utf-8'))

    # 启动两个线程分别接收和发送消息
    threading.Thread(target=receive_message, daemon=True).start()
    threading.Thread(target=send_message, daemon=True).start()

    while True:
        pass  # 保持主线程运行

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 12345))
    server_socket.listen(1)
    print("服务端在端口 12345 监听...")

    # Create a secure context
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="D:\chraypt\server\pems\ec-cert.pem", keyfile="D:\chraypt\server\pems\ec-key.pem")

    # Wrap the socket with the secure context
    server_socket = context.wrap_socket(server_socket, server_side=True)

    while True:
        conn, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    try:
        start_server()
    except Exception as e:
        print(f"ERROR: {e}")