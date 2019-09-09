from enum import Enum

__all__ = ["SignatureType", "EntryType", "PurposeType"]


class SignatureType(Enum):
    EdDSA = "Ed25519"
    ECDSA = "ECDSASecp256k1"
    RSA = "RSA"


class EntryType(Enum):
    Create = "DIDManagement"
    Update = "DIDUpdate"


class PurposeType(Enum):
    PublicKey = "publicKey"
    AuthenticationKey = "authentication"
