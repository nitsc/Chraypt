# 概述
![Chraypt](https://github.com/user-attachments/assets/da9b0294-479e-4814-a377-a934ef4ee8b6)
一个以保障人权为核心理念的命令行通讯软件，专注于信息安全与隐私保护。目前已实现哈希验证身份和TSL通信等基础功能，为用户提供可靠的隐私保障。

# 宗旨
我们坚信每个人都有自己的人权。

# 目标标准
## 加密算法
### 对称加密：用于加密大量数据，速度快
- **AES**(Advanced Encryption Standard)：广泛应用于通信协议（如TLS） **(已实现)**
- **ChaCha20**： 一种流密码，通常与 Poly1305 消息认证码结合使用，提供高效且安全的加密和认证
- **SM4**：中国国家密码局发布的商用密码算法，在中国的金融和政府部门得到广泛应用

### 非对称加密
- **RSA**：常用于密钥交换
- **ECC**(Elliptic Curve Cryptography)：比RSA效率更高，适合移动设备 **(已实现)**
- **SM2**：一种中国国家密码局（国家密码管理局）发布的椭圆曲线公钥密码算法标准
- **NTRU**(Nth Degree Truncated Polynomial Ring Units)： 是一种基于格（Lattice）的公钥密码算法
- **Lattice-based Cryptography**： 基于格的密码学
- **Code-based Cryptography**：是一种后量子密码学方法，它使用纠错码理论中的难题来构建密码系统

## 密钥交换算法
- **Diffie-Hellman** (DH)：用于安全地生成共享密钥 **(取消，因为密钥ECDH高效，而且量子安全性低)**
- **ECDH** (Elliptic Curve Diffie-Hellman)：基于椭圆曲线，更高效 **(已实现)**
- **Kyber**: 是一个基于格的密钥交换协议，已经进入了 NIST 后量子加密标准化项目 的候选方案
- **CSIDH** (Commutative Supersingular Isogeny Diffie-Hellman) 是一种基于超奇异椭圆曲线同源的后量子密钥交换协议 **(取消，因为目前没有成熟的CSIDH库)**

## 数字签名算法
- **ECDSA**(Elliptic Curve Digital Signature Algorithm)：是一种广泛使用的数字签名算法，它基于椭圆曲线密码学 (ECC)
- **RSA签名**：基于大数分解的数学难题
- **SM2**：基于椭圆曲线离散对数难题
- **EdDSA**（Edwards-curve Digital Signature Algorithm）：基于 Edwards 曲线的数字签名算法

## 哈希算法
- **SHA3-512**, **SHA3-384**, **SHA3-256**, **SHA2-512**，**SHA2-256**：广泛使用，安全性高 **(已实现部分)**
- **Argon2**: 专门设计用于抵抗 GPU 和 ASIC 等硬件加速的暴力破解攻击
- **BLAKE3**：非常现代且高性能
- **SM3**： 中国国家密码局发布的密码哈希算法标准

## 随机数生成算法
- **CSPRNG** (Cryptographically Secure Pseudo-Random Number Generator)

## 通信协议
- **TLS**: (Transport Layer Security)：实现加密传输、身份验证 **(已实现,但是由于 SSL 不信任自签名证书，暂时取消客户端验证)**
- **Noise Protocol Framework**：适用于现代通讯软件
- **Tor**： 接入Tor网络
- **I2P**：接入I2P网络

## 零知识证明
- zk-SNARKs, zk-STARKs

# 缺点与不足
以下是来自 ChatGPT-4o mini 的分析：[分析报告](https://chatgpt.com/share/678b8087-88d8-8008-b6cc-e2c74efe3fdf)
