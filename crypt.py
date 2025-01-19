from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

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
        # 提取iv，tag和密文
        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]

        cipher = Cipher(algorithms.AES(shared_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_data.decode('utf-8')