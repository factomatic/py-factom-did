from base64 import urlsafe_b64encode, urlsafe_b64decode
from Crypto.Cipher import AES
from Crypto.Hash import (SHA256, HMAC)
from Crypto.Protocol.KDF import PBKDF2
import json
import os

__all__ = ['encrypt_keys', 'decrypt_keys_from_str', 'decrypt_keys_from_json', 'decrypt_keys_from_ui_store_file']


def encrypt_keys(keys, password):
    """
    Encrypts keys with a password.

    Parameters
    ----------
    keys: KeyModel[]
        A list of keys (management or did) to be encrypted.
    password: str
        A password to use for the encryption of the keys.

    Returns
    -------
    obj
        An object containing salt, initial vector, tag and encrypted data.
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
    encrypted_data, tag = cipher.encrypt_and_digest(data)

    return {
        'salt': sa,
        'iv': iv,
        'tag': tag,
        'data': encrypted_data
    }


def decrypt_keys_from_str(cipher_text_b64, password):
    """
    Decrypts keys from cipher text and password.

    Parameters
    ----------
    cipher_text_b64: str
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

    cipher_text_bin = urlsafe_b64decode(cipher_text_b64)
    salt, cipher_text_bin = cipher_text_bin[:32], cipher_text_bin[32:]
    iv, cipher_text_bin = cipher_text_bin[:16], cipher_text_bin[16:]
    tag, encrypted_data = cipher_text_bin[:16], cipher_text_bin[16:]

    decrypted_keys = _decrypt_keys(salt, iv, encrypted_data, password)
    return decrypted_keys


def decrypt_keys_from_json(encrypted_keys_json, password):
    """
    Decrypts keys from JSON and password.

    Parameters
    ----------
    encrypted_keys_json: str
        JSON containing encrypted keys data.
    password: str
        A password used for the encryption of the keys.

    Returns
    -------
    list
        A list of decrypted keys objects.

    Raises
    ------
    ValueError
        If the JSON or the password used for the encryption is invalid.
    """
    try:
        encrypted_keys_obj = json.loads(encrypted_keys_json)
    except json.decoder.JSONDecodeError:
        raise ValueError('Invalid JSON file.')

    salt = urlsafe_b64decode(encrypted_keys_obj['encryptionAlgo']['salt'])
    iv = urlsafe_b64decode(encrypted_keys_obj['encryptionAlgo']['iv'])
    encrypted_data = urlsafe_b64decode(encrypted_keys_obj['data'])

    decrypted_keys = _decrypt_keys(salt, iv, encrypted_data, password)
    return decrypted_keys


def decrypt_keys_from_ui_store_file(file_path, password):
    """
    Decrypts keys from cipher text, password, salt and initial vector.

    Parameters
    ----------
    file_path: str
        Path to a file to read from.
    password: str
        A password used for the encryption of the keys.

    Returns
    -------
    list
        A list of decrypted keys objects.

    Raises
    ------
    ValueError
        If the file or the password is invalid.
    """

    with open(file_path, 'r') as encrypted_file:
        encrypted_file_content = encrypted_file.read()
        print(encrypted_file_content)

        try:
            encrypted_keys_obj = json.loads(encrypted_file_content)
        except json.decoder.JSONDecodeError:
            raise ValueError('Invalid JSON file.')

        salt = urlsafe_b64decode(encrypted_keys_obj['encryptionAlgo']['salt'])
        iv = urlsafe_b64decode(encrypted_keys_obj['encryptionAlgo']['iv'])
        encrypted_data = urlsafe_b64decode(encrypted_keys_obj['data'])

        key = PBKDF2(
            password, salt,
            dkLen=32,
            count=10000,
            prf=_hmac256
        )

        try:
            m = _decrypt(key, iv, encrypted_data)
            decoded_store = m.decode('utf-8', 'backslashreplace')

            # ToDo: check trailing characters
            liq = decoded_store.rfind('"')
            decrypted_keys = json.loads(json.loads(decoded_store[0:liq + 1]))
            return decrypted_keys
        except json.decoder.JSONDecodeError:
            raise ValueError('Invalid encrypted data or password.')


def _decrypt_keys(salt, iv, encrypted_data, password):
    key = PBKDF2(
        password, salt,
        dkLen=16,
        count=1000,
        prf=_hmac256
    )

    try:
        m = _decrypt(key, iv, encrypted_data)
        return json.loads(m.decode('utf8'))
    except json.decoder.JSONDecodeError:
        raise ValueError('Invalid encrypted data or password.')


def _hmac256(secret, m):
    return HMAC.new(key=secret, msg=m, digestmod=SHA256).digest()


def _decrypt(key, iv, ciphertext):
    decryptor = AES.new(key=key, mode=AES.MODE_GCM, nonce=iv)
    plaintext = decryptor.decrypt(ciphertext)
    return plaintext
