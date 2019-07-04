import os
import json
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import (SHA256, HMAC)
from base64 import urlsafe_b64encode, urlsafe_b64decode

__all__ = ['encrypt_keys', 'decrypt_keys', 'decrypt_keys_from_ui_store']


def encrypt_keys(keys, password):
    """
     encrypts keys with a password and returns cipher text

     :type keys: KeyModel[]
     :type password: str
     :return ctx_b64: str
    """

    keys_data = list(map(lambda k: {
        'alias': k.alias,
        'type': k.type,
        'privateKey': str(k.private_key, 'utf8')
    }, keys))

    data = bytes(json.dumps(keys_data), 'utf8')

    sa = os.urandom(32)
    iv = os.urandom(16)
    iter_cnt = 1000

    key = PBKDF2(
        password=password,
        salt=sa,
        dkLen=16,
        count=iter_cnt,
        prf=_hmac256
    )

    cipher = AES.new(key=key, mode=AES.MODE_GCM, nonce=iv)
    ctx, tag = cipher.encrypt_and_digest(data)

    ctx_b64 = urlsafe_b64encode(sa + iv + tag + ctx)
    return str(ctx_b64, 'utf8')


def decrypt_keys(ctx_b64, password):
    """
    decrypts keys from cipher text and password

    :type ctx_b64: str
    :type password: str
    :return decrypted_keys: []
    """

    ctx_bin = urlsafe_b64decode(ctx_b64)
    sa, ctx_bin = ctx_bin[:32], ctx_bin[32:]
    iv, ctx_bin = ctx_bin[:16], ctx_bin[16:]
    tag, ctx = ctx_bin[:16], ctx_bin[16:]

    key = PBKDF2(
        password, sa,
        dkLen=16,
        count=1000,
        prf=_hmac256
    )

    try:
        m = _decrypt(key, iv, ctx)
        decrypted_keys = json.loads(m.decode('utf8'))
        return decrypted_keys
    except Exception as e:
        raise ValueError(e)


def decrypt_keys_from_ui_store(ctx_b64, password, salt, vector):
    """
    decrypts keys from cipher text, password, salt and initial vector

     :type ctx_b64: str
     :type password: str
     :type salt: str
     :type vector: str
     :return decrypted_keys: []
    """

    sa = urlsafe_b64decode(salt)
    iv = urlsafe_b64decode(vector)
    ctx = urlsafe_b64decode(ctx_b64)
    key = PBKDF2(
        password, sa,
        dkLen=32,
        count=10000,
        prf=_hmac256
    )

    try:
        m = _decrypt(key, iv, ctx)
        decoded_store = m.decode('utf-8', 'backslashreplace')
        liq = decoded_store.rfind('"')
        decrypted_keys = json.loads(json.loads(decoded_store[0:liq + 1]))
        return decrypted_keys
    except Exception as e:
        raise ValueError(e)


def _hmac256(secret, m):
    return HMAC.new(key=secret, msg=m, digestmod=SHA256).digest()


def _decrypt(key, iv, ciphertext):
    decryptor = AES.new(key=key, mode=AES.MODE_GCM, nonce=iv)
    plaintext = decryptor.decrypt(ciphertext)
    return plaintext
