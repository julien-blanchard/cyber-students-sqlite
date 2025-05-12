from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import os

def encryptToChaCha(path_to_key,path_to_nonce,plaintext_to_encrypt):
    key_as_bytes = bytes(path_to_key,"utf-8")
    nonce_as_bytes = bytes.fromhex(path_to_nonce)
    plaintext_as_bytes = bytes(plaintext_to_encrypt, "utf-8")
    chacha20_cipher = Cipher(
        algorithms
        .ChaCha20(
            key_as_bytes,
            nonce_as_bytes,
        ),
        mode=None
        )
    chacha20_encryptor = chacha20_cipher.encryptor()
    result = chacha20_encryptor.update(plaintext_as_bytes)
    return result

def decryptFromChaCha(path_to_key,path_to_nonce,cipher_to_decrypt):
    key_as_bytes = bytes(path_to_key,"utf-8")
    nonce_as_bytes = bytes.fromhex(path_to_nonce)
    cipher_as_bytes = bytes.fromhex(cipher_to_decrypt)
    chacha20_cipher = Cipher(
        algorithms
        .ChaCha20(
            key_as_bytes,
            nonce_as_bytes
        ),
        mode=None
        )
    chacha20_decryptor = chacha20_cipher.decryptor()
    result = chacha20_decryptor.update(cipher_as_bytes)
    return result

def hashToScrypt(path_to_password):
    salt = os.urandom(16)
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2 ** 14,
        r=8,
        p=1
    )
    passphrase_as_bytes = bytes(path_to_password, "utf-8")
    result = kdf.derive(passphrase_as_bytes)
    return result, salt

def dehashFromScrypt(path_to_password, path_to_hashed_password, path_to_salt):
    salt_as_bytes = bytes.fromhex(path_to_salt)
    password_as_bytes = bytes(path_to_password, "utf-8")
    key_as_bytes = bytes.fromhex(path_to_hashed_password)

    kdf = Scrypt(
        salt=salt_as_bytes,
        length=32,
        n=2 ** 14,
        r=8,
        p=1
    )
    try:
        result = kdf.verify(password_as_bytes,key_as_bytes)
        return result
    except:
        return 0