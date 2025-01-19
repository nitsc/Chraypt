from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from cryptography.hazmat.primitives.asymmetric import x25519
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
import binascii
import hashlib


# 使用相同的salt，避免随机值
SALT = b'fixed_salt_value'

class EcdhAesCrypt:
    def __init__(self,):
        pass

    # 生成ECC密钥对（ECDH）
    def generate_ecc_keypair():
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    def generate_shared_key(private_key, peer_public_key):
        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
        # 使用固定的salt值来派生共享密钥
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=SALT, iterations=100000, backend=default_backend())
        derived_key = kdf.derive(shared_key)
        return derived_key

    # 加密数据
    def encrypt_data(shared_key, data):
        # 创建AES加密器（使用GCM模式）
        iv = os.urandom(12)  # 随机生成初始向量
        cipher = Cipher(algorithms.AES(shared_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # 加密数据
        ciphertext = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext

    # 解密数据
    def decrypt_data(shared_key, encrypted_data):
        if encrypted_data is None:
            print('消息：', encrypted_data)
            pass

        # 提取iv，tag和密文
        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]

        cipher = Cipher(algorithms.AES(shared_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_data.decode('utf-8')


class Curve25519Sm4:
    def __init__(self):
        # 生成私钥
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.crypt_sm4 = CryptSM4()

    def get_public_key(self):
        """返回公钥"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def get_private_key(self):
        """返回私钥 (原始字节)"""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

    def generate_shared_key(self, remote_public_key_bytes):
        """与远程公钥交换，生成共享密钥"""
        remote_public_key = x25519.X25519PublicKey.from_public_bytes(remote_public_key_bytes)
        shared_key = self.private_key.exchange(remote_public_key)
        return shared_key

    def str_to_strBin(self, hex_str):
        return binascii.unhexlify(hex_str.hex())

    def encrypt_ecb(self, encrypt_key, value):
        # 使用传入的密钥设置加密模式
        self.crypt_sm4.set_key(binascii.a2b_hex(encrypt_key), SM4_ENCRYPT)
        encrypt_value = self.crypt_sm4.crypt_ecb(value)  # 直接传入字节类型的value
        return binascii.b2a_hex(encrypt_value).decode('utf-8')  # 返回十六进制字符串

    def decrypt_ecb(self, decrypt_key, encrypt_value):
        # 确保传入的字符串是偶数长度的十六进制字符串
        if len(encrypt_value) % 2 != 0:
            encrypt_value = b'0' + encrypt_value  # 在奇数长度的字符串前加上'0'

        try:
            # 确保encrypt_value是有效的十六进制
            encrypt_value_bytes = binascii.a2b_hex(encrypt_value)
        except binascii.Error as e:
            print(f"Error: Invalid hexadecimal string - {e}")
            return None

        # 使用传入的密钥设置解密模式
        self.crypt_sm4.set_key(binascii.a2b_hex(decrypt_key), SM4_DECRYPT)
        decrypt_value = self.crypt_sm4.crypt_ecb(encrypt_value_bytes)
        return self.str_to_strBin(decrypt_value)


from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


class Ed25519:
    def __init__(self):
        # 生成 Ed25519 私钥
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def serialize_private_key(self):
        """将私钥序列化为 PEM 格式"""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def serialize_public_key(self):
        """将公钥序列化为 PEM 格式"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def sign_message(self, message: bytes):
        """用私钥签名消息"""
        return self.private_key.sign(message)

    def verify_signature(self, signature: bytes, message: bytes, public_key_bytes: bytes):
        """用传入的公钥验证签名"""
        try:
            # 反序列化公钥
            public_key = serialization.load_pem_public_key(public_key_bytes)

            # 用反序列化后的公钥验证签名
            public_key.verify(signature, message)
            return True
        except InvalidSignature:
            # 捕获 InvalidSignature 异常后，可以根据场景进一步判断
            return "签名验证失败：签名或消息不匹配"
        except Exception as e:
            # 捕获其他异常并输出
            return f"验证过程中发生错误: {str(e)}"

class Hasher:
    def __init__(self):
        pass

    def double_hash(self, data, salt, sugar):
        # 将数据转换为字节类型
        data_bytes = data.encode('utf-8')
        salt = salt.encode('utf-8')
        sugar = sugar.encode('utf-8')

        # 将盐加到数据上
        salted_data = data_bytes + salt
        # 对盐化后的数据进行 SHA-512 哈希
        salted_hash = hashlib.sha512(salted_data).digest()

        # 将糖加到盐化后的哈希值上
        sugared_data = salted_hash + sugar

        # 对加糖后的数据进行 SHA-256 哈希，然后再进行 SHA3-512 哈希
        return hashlib.sha3_512(hashlib.sha512(sugared_data).digest()).hexdigest()
