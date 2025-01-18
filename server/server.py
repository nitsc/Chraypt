import socket  # 导入 socket 模块，用于创建和管理网络通信
import threading  # 导入 threading 模块，用于多线程处理
import ssl  # 导入 ssl 模块，用于加密通信
import hashlib  # 导入 hashlib 模块，用于生成哈希值
from datetime import datetime  # 导入 datetime 模块，用于获取和显示当前时间

# 定义密钥，客户端和服务端都会使用这个密钥
key = ''''
viGtdaBMJ.CfdbM34FCDKmwT;0kX!l%/chtcpGt,/pI:\iR!Tl"jmUFh/56)7yI3A0+V=.8R164(NTidV}y9HLLuSdEEw318|LkPw$t]y**<'0~ol+[y6}(T,,nInF*){*D]l'Gn;Xj0.oTCg6qaL*U>xw"cV(h$Vre$0jcmH7NH)qys!J}kmX45F|!)X}NrS+G@7?|&$}v\-KlfSm1g>od^g+3Z0582N:x?;l\vT@@3'JI?:Y~Fjn5h[\[?^Bt<*C0_&r]t-,N9DBeuTu$:!wE4p/qr4)!gqmkBF03]3LuKuUW2a,7VAm+NCcLpmre(HB@pP8$}3!yOeIZ^U{&~L5X5CIdtv#L%JJ-PLkXABHLwt#3@9L[dw2,qmC,j1PIL7M!j/:sO_W!48FvkjNrdBA^=]LJZB"XX<c]O1Nw<JDjqZsxz\]D^+od+z0#ADF*"V'CX-!=#2rxC}1]n)s3Im/Q(V[1nIjK1#$M+B(M4{8KBg^k4V=>nAsk+sD\
'''.encode('utf-8')  # 将密钥编码为 UTF-8 格式

# 定义双重哈希函数
def double_hash(data):
    """使用 SHA3-512 和 SHA2-512 进行双重哈希"""
    sha2_hash = hashlib.sha512(data).digest()  # 使用 SHA2-512 算法生成哈希值（输出二进制格式）
    sha3_hash = hashlib.sha3_512(sha2_hash).hexdigest()  # 使用 SHA3-512 算法对上一步结果再次哈希（输出十六进制字符串）
    return sha3_hash  # 返回最终的哈希值

# 处理单个客户端连接
def handle_client(conn, addr):
    print(f"建立连接: {addr}")  # 打印客户端的地址信息

    # 接收客户端发送的哈希值
    client_hash = conn.recv(1024).decode('utf-8')  # 接收数据并解码为字符串
    print(f"收到客户端的哈希值: {client_hash}")

    # 验证客户端传递的哈希值是否匹配
    server_hash = double_hash(key)  # 服务端计算密钥的双重哈希值
    if client_hash != server_hash:  # 如果哈希值不匹配
        print("哈希值不匹配，拒绝连接！")
        conn.close()  # 关闭连接
        return  # 终止处理

    print("哈希值验证通过，开始通信.")

    # 定义接收消息的函数
    def receive_message():
        while True:
            try:
                data = conn.recv(1024).decode('utf-8')  # 接收最大 1024 字节并解码
                if not data:  # 如果收到空数据，表示客户端断开
                    print("客户端断开连接.")
                    break
                print(f"\n客户端: {data}", datetime.now())  # 打印收到的消息和当前时间
            except ConnectionResetError:  # 捕获客户端连接重置的异常
                print("客户端重置连接.")
                break

    # 定义发送消息的函数
    def send_message():
        while True:
            response = input("服务端: ")  # 获取用户输入
            if response.lower() == 'exit':  # 如果输入 'exit'，退出发送
                break
            conn.send(response.encode('utf-8'))  # 编码消息并发送

    # 启动两个线程分别处理消息接收和发送
    threading.Thread(target=receive_message, daemon=True).start()  # 启动接收线程
    threading.Thread(target=send_message, daemon=True).start()  # 启动发送线程

    while True:
        pass  # 主线程保持运行以防程序退出

# 启动服务端
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 创建一个 TCP/IP 套接字
    server_socket.bind(('0.0.0.0', 12345))  # 将套接字绑定到所有可用的网络接口，端口 12345
    server_socket.listen(1)  # 开始监听连接，请求队列最大长度为 1
    print("服务端在端口 12345 监听...")

    # 创建 SSL 加密上下文
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)  # 指定 SSL 用于客户端验证
    context.load_cert_chain(certfile="D:\chraypt\server\pems\ec-cert.pem", keyfile="D:\chraypt\server\pems\ec-key.pem")  # 加载服务器的证书和私钥

    # 使用 SSL 包装套接字
    server_socket = context.wrap_socket(server_socket, server_side=True)  # 指定作为服务器使用 SSL

    while True:
        conn, addr = server_socket.accept()  # 接受一个客户端连接
        threading.Thread(target=handle_client, args=(conn, addr)).start()  # 为每个客户端启动一个新线程

# 主程序入口
if __name__ == "__main__":
    try:
        start_server()  # 启动服务端
    except Exception as e:  # 捕获并处理异常
        print(f"ERROR: {e}")
