from enum import Enum

__all__ = ['SignatureType', 'EntryType']


class SignatureType(Enum):
    EdDSA = 'Ed25519'
    ECDSA = 'ECDSASecp256k1'
    RSA = 'RSA'


class EntryType(Enum):
    Create = 'DIDManagement'
    Update = 'DIDUpdate'
