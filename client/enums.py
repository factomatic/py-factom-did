from enum import Enum

__all__ = ["KeyType", "EntryType", "DIDKeyPurpose"]


class KeyType(Enum):
    EdDSA = "Ed25519VerificationKey"
    ECDSA = "ECDSASecp256k1VerificationKey"
    RSA = "RSAVerificationKey"


class EntryType(Enum):
    Create = "DIDManagement"
    Update = "DIDUpdate"
    VersionUpgrade = "DIDMethodVersionUpgrade"
    Deactivation = "DIDDeactivation"


class DIDKeyPurpose(Enum):
    PublicKey = "publicKey"
    AuthenticationKey = "authentication"
