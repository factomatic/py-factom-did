from base64 import urlsafe_b64decode
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Protocol.KDF import PBKDF2
import json
import os

__all__ = [
    "encrypt_keys",
    "decrypt_keys_from_str",
    "decrypt_keys_from_json_str",
    "decrypt_keys_from_json_file",
]


def encrypt_keys(management_keys, did_keys, password):
    """
    Encrypts keys with a password.

    Parameters
    ----------
    management_keys: ManagementKeyModel[]
        A list of management keys to be encrypted.
    did_keys: DidKeyModel[]
        A list of did keys to be encrypted.
    password: str
        A password to use for the encryption of the keys.

    Returns
    -------
    obj
        An object containing salt, initial vector, tag and encrypted data.
    """

    management_keys_dict = {
        k.alias: str(k.private_key, "utf8") for k in management_keys
    }

    did_keys_dict = {k.alias: str(k.private_key, "utf8") for k in did_keys}

    keys_data = {"managementKeys": management_keys_dict, "didKeys": did_keys_dict}

    data = bytes(json.dumps(keys_data), "utf8")

    salt = os.urandom(32)
    iv = os.urandom(16)

    key = _gen_key(password, salt)
    cipher = AES.new(key=key, mode=AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    return {"salt": salt, "iv": iv, "data": ciphertext + tag}


def decrypt_keys_from_str(cipher_text_b64, password, encryption_algo="AES-GCM"):
    """
    Decrypts keys from cipher text and password.

    Parameters
    ----------
    cipher_text_b64: str
        Base 64 encoded cipher text.
    password: str
        A password used for the encryption of the keys.
    encryption_algo: str
        The encryption algorithm used. Currently only 'AES-GCM' is supported

    Returns
    -------
    obj
        An object containing dictionaries of decrypted management and did keys.

    Raises
    ------
    ValueError
        If the cipher text or the password used for the encryption is invalid.
    """

    cipher_text_bin = urlsafe_b64decode(cipher_text_b64)
    salt, cipher_text_bin = cipher_text_bin[:32], cipher_text_bin[32:]
    iv, cipher_text_bin = cipher_text_bin[:16], cipher_text_bin[16:]
    ciphertext = cipher_text_bin[:-16]

    return _decrypt_keys(salt, iv, ciphertext, password, encryption_algo)


def decrypt_keys_from_json_str(encrypted_keys_json_str, password):
    """
    Decrypts keys from JSON string and password. The JSON string must have a
    schema compatible with the one produced by
    DID.export_encrypted_keys_as_json():

    '{
        "encryptionAlgo": {
            "salt": ...,
            "iv": ...,
            "name": ...,
            "tagLength": ...,
        },
        "data": ... (encrypted private keys),
        "did": ...
    }'

    Parameters
    ----------
    encrypted_keys_json_str: str
        JSON string containing encrypted keys data.
    password: str
        A password used for the encryption of the keys.

    Returns
    -------
    obj
        An object containing dictionaries of decrypted management and did keys.

    Raises
    ------
    ValueError
        If the JSON or the password used for the encryption is invalid.
    """
    try:
        encrypted_keys_json = json.loads(encrypted_keys_json_str)
    except json.decoder.JSONDecodeError:
        raise ValueError("Invalid JSON file.")

    return _decrypt_keys_from_json(encrypted_keys_json, password)


def decrypt_keys_from_json_file(file_path, password):
    """
    Decrypts keys from JSON file and password. The file must contain valid JSON
    with a schema compatible with the one produced by
    DID.export_encrypted_keys_as_json(). See decrypt_keys_from_json_str for
    details.

    Parameters
    ----------
    file_path: str
        Path to a file to read from.
    password: str
        A password used for the encryption of the keys.

    Returns
    -------
    obj
        An object containing dictionaries of decrypted management and did keys.

    Raises
    ------
    ValueError
        If the file or the password is invalid.
    """

    with open(file_path, "r") as encrypted_file:
        try:
            encrypted_keys_json = json.load(encrypted_file)
        except json.decoder.JSONDecodeError:
            raise ValueError("Invalid JSON file.")

    return _decrypt_keys_from_json(encrypted_keys_json, password)


def _decrypt_keys_from_json(encrypted_keys_json, password):
    salt = urlsafe_b64decode(encrypted_keys_json["encryptionAlgo"]["salt"])
    iv = urlsafe_b64decode(encrypted_keys_json["encryptionAlgo"]["iv"])
    encrypted_data = urlsafe_b64decode(encrypted_keys_json["data"])

    tag_length = int(encrypted_keys_json["encryptionAlgo"]["tagLength"])
    ciphertext = encrypted_data[: -int(tag_length / 8)]

    encryption_algo = encrypted_keys_json["encryptionAlgo"]["name"]

    return _decrypt_keys(salt, iv, ciphertext, password, encryption_algo)


def _decrypt_keys(salt, iv, ciphertext, password, encryption_algo):
    try:
        m = _decrypt(iv, ciphertext, password, salt, encryption_algo)
        return json.loads(m.decode("utf8"))
    except json.decoder.JSONDecodeError:
        raise ValueError("Invalid encrypted data or password.")


def _hmac256(secret, m):
    return HMAC.new(key=secret, msg=m, digestmod=SHA256).digest()


def _decrypt(iv, ciphertext, password, salt, encryption_algo):
    if encryption_algo != "AES-GCM":
        raise NotImplementedError("Currently only AES-GCM is supported!")

    key = _gen_key(password, salt)
    decryptor = AES.new(key=key, mode=AES.MODE_GCM, nonce=iv)
    return decryptor.decrypt(ciphertext)


def _gen_key(password, salt):
    return PBKDF2(password, salt, dkLen=32, count=10000, prf=_hmac256)
