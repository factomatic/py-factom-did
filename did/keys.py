import base58
from Crypto.PublicKey import RSA
from ecdsa import SigningKey, SECP256k1
import ed25519

from did.enums import SignatureType

__all__ = ["KeyPair", "AbstractDIDKey", "ManagementKey", "DIDKey"]


class KeyPair:
    """
    Represents a cryptographic key pair, consisting of a public key and its corresponding private key.

    Attributes
    ----------
    public_key: str
        The public key, encoded in base58.
    private_key: str
        The private key, encoded in base58.
    """

    def __init__(self, public_key, private_key):
        self.public_key = public_key
        self.private_key = private_key


class AbstractDIDKey(KeyPair):
    """
    Represents the common fields in a ManagementKey and a DidKey.

    Attributes
    ----------
    public_key: str
        The public key, encoded in base58.
    private_key: str
        The private key, encoded in base58.
    signature_type: SignatureType
        Identifies the type of signature that the key pair can be used to generate and verify.
    alias: str
        A human-readable nickname for the key.
    controller: str
        An entity that controls the key.
    priority_requirement: int
        A non-negative integer showing the minimum hierarchical level a key must have in order to remove this key.
    """

    def __init__(
        self,
        public_key,
        private_key,
        signature_type,
        alias,
        controller,
        priority_requirement,
    ):
        super().__init__(public_key, private_key)
        self.signature_type = signature_type
        self.alias = alias
        self.controller = controller
        self.priority_requirement = priority_requirement

    def generate_key_pair(self):
        """
        Generates a new key pair.

        Returns
        -------
        KeyPairModel
            A KeyPairModel containing public and private key.

        Raises
        ------
        RuntimeError
            If an supported signature type is used.
        """

        if self.signature_type == SignatureType.EdDSA.value:
            return self._generate_ed_dsa_key_pair()
        elif self.signature_type == SignatureType.ECDSA.value:
            return self._generate_ec_dsa_key_pair()
        elif self.signature_type == SignatureType.RSA.value:
            return self._generate_rsa_key_pair()
        else:
            raise RuntimeError("Invalid signature type.")

    @staticmethod
    def _generate_ed_dsa_key_pair():
        signing_key, verifying_key = ed25519.create_keypair()
        key_pair = KeyPair(
            base58.b58encode(verifying_key.to_bytes()),
            base58.b58encode(signing_key.to_bytes()),
        )
        return key_pair

    @staticmethod
    def _generate_ec_dsa_key_pair():
        signing_key = SigningKey.generate(curve=SECP256k1)
        verifying_key = signing_key.get_verifying_key()
        key_pair = KeyPair(
            base58.b58encode(verifying_key.to_string()),
            base58.b58encode(signing_key.to_string()),
        )
        return key_pair

    @staticmethod
    def _generate_rsa_key_pair():
        key = RSA.generate(2048)
        key_pair = KeyPair(key.publickey().export_key(), key.export_key())
        return key_pair


class ManagementKey(AbstractDIDKey):
    """
    A key used to sign updates for an existing DID.

    Attributes
    ----------
    public_key: str
    private_key: str
    signature_type: SignatureType
    alias: str
    controller: str
    priority_requirement: int
    priority: int
        A non-negative integer showing the hierarchical level of the key. Keys with lower priority override keys with
        higher priority.
    """

    def __init__(
        self,
        public_key,
        private_key,
        signature_type,
        alias,
        controller,
        priority_requirement,
        priority,
    ):
        super().__init__(
            public_key,
            private_key,
            signature_type,
            alias,
            controller,
            priority_requirement,
        )
        self.priority = priority


class DIDKey(AbstractDIDKey):
    """
    Application-level key, which can be used for authentication, signing requests, encryption, decryption, etc.

    Attributes
    ----------
    public_key: str
    private_key: str
    signature_type: SignatureType
    alias: str
    controller: str
    priority_requirement: int
    purpose: PurposeType[]
        A list of PurposeTypes showing what purpose(s) the key serves. (PublicKey, AuthenticationKey or both)
    """

    def __init__(
        self,
        public_key,
        private_key,
        signature_type,
        alias,
        controller,
        priority_requirement,
        purpose,
    ):
        super().__init__(
            public_key,
            private_key,
            signature_type,
            alias,
            controller,
            priority_requirement,
        )
        self.purpose = purpose
