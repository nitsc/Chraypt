from datetime import datetime

import blake3
from argon2 import PasswordHasher
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
SALT = b'''09417ec5dd7f3adec25d45122afec72ab7a4fe6d1fa176d318f1310fcbf8af4ade7ac07873797a8aba240764fdeb64d4d193bb21421a59c04563cf03a9b52b7861aa23e820146bb280a2da55a81b64444574b5885a6b0335506389a06f5c5bdb499ac92e9b4fb7adb494fb08030ce1a1136d54e6e826603e484b2c748be222d50644d5dbfe798aeeaac1bb2b6df8e04e1b9cd74a5dd3af6821c7a41c7ad99d2e89195444c744e8402c83887812302062f72fff8654191f6d3bab0d6c7bf170b387e2e3ab3fa303cbf183df3d8a415801a717c84140780eb64fa1d1b3c0e3bb0a2be3eaf971306d078a5d327e313e4d440b1d3b81c9a8efb0394e8625915feaf21c0ebb9963d1f98120338f3b6d334470f5a1645ac7a9950a61a41db228f0837d126a2aa42abe362e42f6ebfdb8a3f6305fe14947bb8ef2cc1eb690a65361711dfc9e326ef30636af528da0a4f7cb9f7b4a3fce0e71177f0cbcbd89d1ca8c0d35261502b01e087f1bfebf88ad54784d84b8802069fd8bf915a02c1017873092a73904ad6dcf93abe38e637e9f3d79e0928f89409dc2afa16e719163fcf0f99d3558c620511366bb7b1e98f688bf2f221a44c271ce31959c74372f8e6232597726e47b7b6fd2423932acee89cd96530c4edfae2a22d7bdebc9407c618924634983c11f76718467158773af916112155808a68854d4592956b6f165e7ac6f1e984f2667cf35e29639ed26119fdf4403d88bfb0a3d10a64e6f3f15efceeaa8128ab03b8cc1db238904f82d5581b6ad7bd76caa20c3b8ed4fa2b36bf648cf0edaddd390b2fdffdacbf91d1f4ca09545ed5166faa9c7523d0ea1148a519821453eb00c44ae45e400ab61ed5cb499ac8bfdd7d70efaca58e75833812894bea3483b43a85d436ebe22f62ae247945de74742b453d66ca91d6741c99106a9699dedca2b3ced538c0eba6bc63473d02abbeac0a53b24a1f0c686cdfcbeee39156d724db472f923b2a9cb8fa02f8fa585fd4e582b0ccd7422baed33faf265f3c6bc51a84a0e340f88e15c23d19b133ed1cce75eaa3df454f3b9e0aabbaeec2dfc935ad869897353f0e27da2af82ccddb8253041f6f4a9ffcc3ea966a37ef596bba5149e09a4bf4361902ac3d5e5d9bd173a0d569f13fc7e47c04e71602f3f49323c8fcf229fb6e305c8e0e92ba434adb077293386d7066504cc5d58399a35d6b9770e530b34ec086cf99772c74fbab561fbd0c8ad2a05e3e3a0644fb3a6a082ead59f1f8fc5001b2269f0e5492eff755afcd63885e8d1ba5a6c7843bd5760ddcbdefe80858ecadb734f8a46631e2f39b53f3927a90b03b72f219c95bffd3bd756e9fcaadd1662f2f9d9d4e7c822e61e3fac10adc65f563624144db984f79c782f259f1a193c8daa870fc34ca4d8546ef83b552701a03dc1b9dc686c1b37b56aa6c9c91ac20885fd25ae2cd102e0eb3a225042249b3c07f5a84bcf318ec364b80cfc23cf781bca14ccc1d2a5fffdc577bc200a2be47e55c07124306f54fa3805cd088a11f3b3692c52db3c487ffca9477982babc121d107e93cc89eb0464421df978c9fbb48e51bdbffcc2cbaa1285e608c6d354f39c37fff9da7c4be49f64816808c358f166d3b577f910b88ae10b782afe1fdd4cb6c5897567ed2950baf76d5bb6d59392af7e58b250c3094ebb9e95297bee470a3d6385eaa50cc45d17434fd2d3d5563bd73bf74f0eda2db0bbf613256b62c09a552bf0b8b75459c2ae9ee55848108076d37b24466012cbbf6d585202d66e2fd8378ef22a1debcdcb1b22175bdb1970706872e37c7d169b4192f92d5481965081803d706867b5574bc08bf1a2f9e992cc10db0eb53f67736f823d5a3999ec4b3d2dd90931c1078781008c09d2241ab14e3d957efd45fdddb89654c1453a1bb1892223a28fc438cbbea6ceadb6d0895122fc3810e3e40b6629ce75a0d153c8c98bfbb87c530e375fa8e9e08e0d51af22acf7a80e6e1a7f08fb9c154b4468bc28f1caa1ce6dc7afa197b330914fc02a00ae19685399270e019cf3eefdbe5c3df3130147177dd34c5c417ad7e0758a366a17400bab89d730dafcb830eb20755b3498f61b616225ec0922ba17807c70101200da33277d2237542e4a04b2a509822d830eaac185e8ed0d612b314e24a442bf7a3a81444635f5889d644ec3aeeb7f2b57e257352240e20ca8c52012a329b3b334ce3719c539ad83bdcd29d807848dcc5a35c78f110be519fa16d91833ad8a2f55603ca6670361daf1bb395bb9a28a93f6e4a832da666309108b3ae3dd3d9868fdacde8adf60886cd8a45202d017e1b4d995431e7c64c198b024bc641d0fdd2d3e3f79d95ae1ede3c7c30308e2ef2e6ab3fd912f6e0e1f8b8beabd02fbb186463e7a5e0024a9fcc5c2a7b684aea61023ee868c4febd2eb0471ddc664a990871490d2a2f20b333f22e5834f438ac603de00d20f4877adf7b9743497f29a3572f2af64944f5e3bc32b2274c484f493667378deaddbbe12f82fc617bf2712dc960e393fe7f487c57c8d0db0e92d82880a6c0ebe804885e2e8c9f01fc11b81a8cf5ae9187a26fb383e4905baa936feda356193fa3dbd5913652f9f61f4c547d8e58341c51f3eba864705334fb713a2c7623ae51f1c41dc39efb9127c3d5b925999dd223be365aad65d0d244ea381bae8689e97437eb736c672969cc4b625ad1d5a8f2ee55df0d668827be1aa1157f31588ef0f471166f8f3acc35ad599af000c7b7f3dbde0c9ec95f18facc9d223f730d73610bb955ef9db10f62f38940c34bd9e9468f49ad7d2afbaad8cb1dd6b4068778482d06dcd709894dc484d40f32c52311acad13750aed90927d8087aeb58eb1a74a0cebab32519e93d2a253ae38aefaa6082a5
'''

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

    def ab33_hash(self, data):
        # 获取年月日时分
        now = datetime.now()
        year = str(now.year)
        month = str(now.month)
        day = str(now.day)
        hour = str(now.hour)
        minute = str(now.minute)
        time_str = f"y{year}m{month}d{day}h{hour}m{minute}"

        # 将数据和时间戳合并
        data_with_timestamp = data + time_str

        # 将数据转换为字节类型
        data_bytes = data_with_timestamp.encode('utf-8')

        # 创建一个密码哈希器
        ph = PasswordHasher()

        # 生成argon2哈希
        hashed_data = ph.hash(data_bytes.decode('utf-8'))  # 对字符串进行哈希

        # 使用blake3处理argon2哈希结果
        hashed_data_bytes = hashed_data.encode('utf-8')
        blake3_hash = blake3.blake3(hashed_data_bytes).hexdigest()

        return blake3_hash

