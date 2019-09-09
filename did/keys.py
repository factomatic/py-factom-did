import base58
from Crypto.PublicKey import RSA
from ecdsa import SigningKey, SECP256k1
import ed25519

from did.enums import SignatureType
from did.models import KeyPairModel

__all__ = ["generate_key_pair"]


def generate_key_pair(signature_type):
    """
    Generates new key pair.

    Parameters
    ----------
    signature_type: str
        Type of signature to be used when creating the key.

    Returns
    -------
    KeyPairModel
        A KeyPairModel containing public and private key.

    Raises
    ------
    RuntimeError
        If invalid signature type is passed.
    """

    if signature_type == SignatureType.EdDSA.value:
        return _generate_ed_dsa_key_pair()
    elif signature_type == SignatureType.ECDSA.value:
        return _generate_ec_dsa_key_pair()
    elif signature_type == SignatureType.RSA.value:
        return _generate_rsa_key_pair()
    else:
        raise RuntimeError("Invalid signature type.")


def _generate_ed_dsa_key_pair():
    signing_key, verifying_key = ed25519.create_keypair()
    key_pair = KeyPairModel(
        base58.b58encode(verifying_key.to_bytes()),
        base58.b58encode(signing_key.to_bytes()),
    )
    return key_pair


def _generate_ec_dsa_key_pair():
    signing_key = SigningKey.generate(curve=SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    key_pair = KeyPairModel(
        base58.b58encode(verifying_key.to_string()),
        base58.b58encode(signing_key.to_string()),
    )
    return key_pair


def _generate_rsa_key_pair():
    key = RSA.generate(2048)
    key_pair = KeyPairModel(key.publickey().export_key(), key.export_key())
    return key_pair
