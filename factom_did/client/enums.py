from enum import Enum

__all__ = ["KeyType", "EntryType", "DIDKeyPurpose", "Network"]


class KeyType(Enum):
    EdDSA = "Ed25519VerificationKey"
    ECDSA = "ECDSASecp256k1VerificationKey"
    RSA = "RSAVerificationKey"

    @staticmethod
    def from_str(string):
        if string == "Ed25519VerificationKey":
            return KeyType.EdDSA
        elif string == "ECDSASecp256k1VerificationKey":
            return KeyType.ECDSA
        elif string == "RSAVerificationKey":
            return KeyType.RSA
        else:
            raise NotImplementedError("Unknown KeyType value: {}".format(string))


class EntryType(Enum):
    Create = "DIDManagement"
    Update = "DIDUpdate"
    VersionUpgrade = "DIDMethodVersionUpgrade"
    Deactivation = "DIDDeactivation"


class DIDKeyPurpose(Enum):
    PublicKey = "publicKey"
    AuthenticationKey = "authentication"

    @staticmethod
    def from_str(string):
        if string == "publicKey":
            return DIDKeyPurpose.PublicKey
        elif string == "authentication":
            return DIDKeyPurpose.AuthenticationKey
        else:
            raise NotImplementedError("Unknown DIDKeyPurpose value: {}".format(string))


class Network(Enum):
    Mainnet = "mainnet"
    Testnet = "testnet"
    Unspecified = ""

    @staticmethod
    def from_str(string):
        if string == "mainnet":
            return Network.Mainnet
        elif string == "testnet":
            return Network.Testnet
        elif string == "":
            return Network.Unspecified
        else:
            raise NotImplementedError("Unknown Network value: {}".format(string))
