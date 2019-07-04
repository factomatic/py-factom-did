import ed25519
import base58
from enums import SignatureType
from models import KeyPairModel
from ecdsa import SigningKey, SECP256k1
from Crypto.PublicKey import RSA

__all__ = ['generate_key_pair']


def generate_key_pair(type):
    """
    generates new key pair

    :type type: str
    :return: KeyPairModel
    """

    if type == SignatureType.EdDSA.value:
        return _generate_ed_dsa_key_pair()
    elif type == SignatureType.ECDSA.value:
        return _generate_ec_dsa_key_pair()
    elif type == SignatureType.RSA.value:
        return _generate_rsa_key_pair()
    else:
        print('Invalid signature type')


def _generate_ed_dsa_key_pair():
    signing_key, verifying_key = ed25519.create_keypair()
    key_pair = KeyPairModel(base58.b58encode(verifying_key.to_bytes()), base58.b58encode(signing_key.to_bytes()))
    return key_pair


def _generate_ec_dsa_key_pair():
    signing_key = SigningKey.generate(curve=SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    key_pair = KeyPairModel(base58.b58encode(verifying_key.to_string()), base58.b58encode(signing_key.to_string()))
    return key_pair


def _generate_rsa_key_pair():
    key = RSA.generate(2048)
    key_pair = KeyPairModel(key.publickey().export_key(), key.export_key())
    return key_pair
