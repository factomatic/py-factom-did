from base64 import urlsafe_b64encode, urlsafe_b64decode
from Crypto.Cipher import AES
from Crypto.Hash import (SHA256, HMAC)
from Crypto.Protocol.KDF import PBKDF2
import json
import os

__all__ = ['encrypt_keys', 'decrypt_keys', 'decrypt_keys_from_ui_store']


def encrypt_keys(keys, password):
    """
    Encrypts keys with a password and returns cipher text.

    Parameters
    ----------
    keys: KeyModel[]
        A list of keys (management or did) to be encrypted.
    password: str
        A password to use for the encryption of the keys.

    Returns
    -------
    str
        Encrypted keys cipher text encoded in base64 format.
    """

    keys_data = list(map(lambda k: {
        'alias': k.alias,
        'type': k.signature_type,
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
    Decrypts keys from cipher text and password.

    Parameters
    ----------
    ctx_b64: str
        Base 64 encoded cipher text.
    password: str
        A password used for the encryption of the keys.

    Returns
    -------
    list
        A list of decrypted keys objects.

    Raises
    ------
    ValueError
        If the cipher text or the password used for the encryption is invalid.
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
    Decrypts keys from cipher text, password, salt and initial vector.

    Parameters
    ----------
    ctx_b64: str
        Base 64 encoded cipher text.
    password: str
        A password used for the encryption of the keys.
    salt: str
        32 bytes of random data encoded in base64 format.
    vector: str
        Initialization vector with 16 bytes size encoded in base64 format.
    Returns
    -------
    list
        A list of decrypted keys objects.

    Raises
    ------
    ValueError
        If one of the parameters is invalid.
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
