# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import os
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from typing import Tuple, BinaryIO

KEY_FOLDER = os.environ['KEY_DIR']


class HashAPI:
    """Class with static methods for generating hashes.

    """

    @staticmethod
    def hash_sha512(input_str: str) -> str:
        """Generate hash SHA-512.

        Args:
            input_str (str): Input string.

        Returns:
            Str with hash in hex format.

        Raises:
            AssertionError: if input string is not set.

        """

        assert input_str, 'Hash: input string is not set'
        hash_obj = hashlib.sha512(input_str.encode())
        return hash_obj.hexdigest()

    @staticmethod
    def hash_md5(input_str: str) -> str:
        """Generate hash MD5.

        Args:
            input_str (str): Input string.

        Returns:
            Str with hash in hex format.

        Raises:
            AssertionError: if input string is not set.

        """

        assert input_str, 'Hash: input string is not set'
        hash_obj = hashlib.md5(input_str.encode())
        return hash_obj.hexdigest()


class BaseCipher:
    """Base cipher class.

    """

    def __init__(self):
        if not os.path.exists(KEY_FOLDER):
            os.mkdir(KEY_FOLDER)

    def encrypt(self, data: bytes):
        """Encrypt data.

        Args:
            data (bytes): Input data for encrypting.

        """

        return data

    def decrypt(self, input_file: BinaryIO, filename: str) -> bytes:
        """Decrypt data.

        Args:
            input_file (BinaryIO): Input file with data for decrypting,
            filename (str): Input filename without extension.

        Returns:
            Bytes with decrypted data.

        """

        return input_file.read()

    def write_cipher_text(self, data: bytes, out_file: BinaryIO, filename: str):
        """Encrypt data and write cipher text into output file.

        Args:
            data (bytes): Encrypted data,
            out_file (BinaryIO): Output file,
            filename (str): Output filename without extension.

        """

        out_file.write(self.encrypt(data))


class AESCipher(BaseCipher):
    """AES cipher class.

    """

    def __init__(self, file_folder: str):
        super().__init__()
        self.file_folder = file_folder

    def encrypt(self, data: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
        """Encrypt data.

        Args:
            data (bytes): Input data for encrypting.

        Returns:
            Tuple with bytes values, which contains cipher text, tag, nonce and session key.

        """

        session_key = get_random_bytes(16)
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        cipher_text, tag = cipher_aes.encrypt_and_digest(data)
        return cipher_text, tag, cipher_aes.nonce, session_key

    def decrypt(self, input_file: BinaryIO, filename: str) -> bytes:
        """Decrypt data.

        Args:
            input_file (BinaryIO): Input file with data for decrypting,
            filename (str): Input filename without extension.

        Returns:
            Bytes with decrypted data.

        """

        nonce, tag, cipher_text = [input_file.read(x) for x in (16, 16, -1)]
        session_key_file = os.path.join(self.file_folder, f'{filename}.bin')
        session_key = open(session_key_file, 'rb').read()
        return self.decrypt_aes_data(cipher_text, tag, nonce, session_key)

    @staticmethod
    def decrypt_aes_data(cipher_text: bytes, tag: bytes, nonce: bytes, session_key: bytes) -> bytes:
        """Decrypt AES data.

        Args:
            cipher_text (bytes): Cipher text for decrypting,
            tag (bytes): AES tag,
            nonce (bytes): AES nonce,
            session_key (bytes): AES session key.

        Returns:
            Bytes with decrypted data.

        """

        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(cipher_text, tag)
        return data

    def write_cipher_text(self, data: bytes, out_file: BinaryIO, filename: str):
        """Encrypt data and write cipher text into output file.

        Args:
            data (bytes): Encrypted data,
            out_file (BinaryIO): Output file,
            filename (str): Output filename without extension.

        """

        cipher_text, tag, nonce, session_key = self.encrypt(data)
        session_key_file = os.path.join(self.file_folder, f'{filename}.bin')

        if not os.path.exists(session_key_file):
            with open(session_key_file, 'wb') as f:
                f.write(session_key)

        out_file.write(nonce)
        out_file.write(tag)
        out_file.write(cipher_text)


class RSACipher(AESCipher):
    """RSA cipher class.

    """
    CODE = os.environ['CRYPTO_CODE']
    KEY_PROTECTION = 'scryptAndAES128-CBC'

    def __init__(self, file_folder: str, user_id: int):
        super().__init__(file_folder)
        if user_id is None:
            raise ValueError("User id needs to be specified for key separation!")
        self.user_id = user_id

        key = RSA.generate(2048)
        encrypted_key = key.export_key(passphrase=self.CODE, pkcs=8, protection=self.KEY_PROTECTION)

        self.private_key_file = os.path.join(KEY_FOLDER, f'private_rsa_{self.user_id}.bin')
        self.public_key_file = os.path.join(KEY_FOLDER, f'public_rsa_{self.user_id}.bin')

        if not os.path.exists(self.private_key_file) or not os.path.exists(self.public_key_file):
            with open(self.private_key_file, 'wb') as f:
                f.write(encrypted_key)

            with open(self.public_key_file, 'wb') as f:
                f.write(key.publickey().exportKey())

    def encrypt(self, data: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
        """Encrypt data.

        Args:
            data (bytes): Input data for encrypting.

        Returns:
            Tuple with bytes values, which contains cipher text, tag, nonce and session key.

        """

        cipher_text, tag, nonce, session_key = super().encrypt(data)

        public_key = RSA.import_key(open(self.public_key_file, 'rb').read())
        cipher_rsa = PKCS1_OAEP.new(public_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        return cipher_text, tag, nonce, enc_session_key

    def decrypt(self, input_file: BinaryIO, filename: str) -> bytes:
        """Decrypt data.

        Args:
            input_file (BinaryIO): Input file with data for decrypting,
            filename (str): Input filename without extension.

        Returns:
            Bytes with decrypted data.

        """

        private_key = RSA.import_key(open(self.private_key_file).read(), passphrase=self.CODE)
        nonce, tag, cipher_text = [input_file.read(x) for x in (16, 16, -1)]
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key_file = os.path.join(self.file_folder, f'{filename}.bin')
        enc_session_key = open(session_key_file, 'rb').read()
        session_key = cipher_rsa.decrypt(enc_session_key)

        return self.decrypt_aes_data(cipher_text, tag, nonce, session_key)

    def write_cipher_text(self, data: bytes, out_file: BinaryIO, filename: str):
        """Encrypt data and write cipher text into output file.

        Args:
            data (bytes): Encrypted data,
            out_file (BinaryIO): Output file,
            filename (str): Output filename without extension.

        """

        cipher_text, tag, nonce, session_key = self.encrypt(data)
        session_key_file = os.path.join(self.file_folder, f'{filename}.bin')

        if not os.path.exists(session_key_file):
            with open(session_key_file, 'wb') as f:
                f.write(session_key)

        out_file.write(nonce)
        out_file.write(tag)
        out_file.write(cipher_text)
