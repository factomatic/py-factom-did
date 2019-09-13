import re

import base58
from Crypto.PublicKey import RSA
from ecdsa import SigningKey, SECP256k1
import ed25519

from did.constants import DID_METHOD_NAME
from did.enums import PurposeType, SignatureType

__all__ = ["AbstractDIDKey", "ManagementKey", "DIDKey"]


class AbstractDIDKey:
    """
    Represents the common fields and functionality in a ManagementKey and a DidKey.

    Attributes
    ----------
    alias: str
        A human-readable nickname for the key.
    signature_type: SignatureType
        Identifies the type of signature that the key pair can be used to generate and verify.
    controller: str
        An entity that controls the key.
    priority_requirement: int
        A non-negative integer showing the minimum hierarchical level a key must have in order to remove this key.
    public_key: str, optional
        The public key, encoded in base58.
    private_key: str, optional
        The private key, encoded in base58.
    """

    def __init__(
        self,
        alias,
        signature_type,
        controller,
        priority_requirement,
        public_key=None,
        private_key=None,
    ):

        self._validate_key_input_params(
            alias,
            signature_type,
            controller,
            priority_requirement,
            public_key,
            private_key,
        )

        self.alias = alias
        self.signature_type = signature_type
        self.controller = controller
        self.priority_requirement = priority_requirement

        if public_key is None and private_key is None:
            self.public_key, self.private_key = self.generate_key_pair()
        else:
            self.public_key, self.private_key = public_key, private_key

    def __eq__(self, other):
        if self.__class__ is other.__class__:
            return (
                self.alias,
                self.signature_type,
                self.controller,
                self.priority_requirement,
                self.public_key,
                self.private_key,
            ) == (
                other.alias,
                other.signature_type,
                other.controller,
                other.priority_requirement,
                other.public_key,
                other.private_key,
            )
        return NotImplemented

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

    def to_entry_dict(self):
        """
        Converts the object to a dictionary suitable for recording on-chain.
        """

        d = vars(self)
        del d["private_key"]
        if self.priority_requirement is None:
            del d["priority_requirement"]
        d["id"] = "{}:{}".format(DID_METHOD_NAME, self.alias)
        return d

    @staticmethod
    def _generate_ed_dsa_key_pair():
        signing_key, verifying_key = ed25519.create_keypair()
        return (
            base58.b58encode(verifying_key.to_bytes()),
            base58.b58encode(signing_key.to_bytes()),
        )

    @staticmethod
    def _generate_ec_dsa_key_pair():
        signing_key = SigningKey.generate(curve=SECP256k1)
        verifying_key = signing_key.get_verifying_key()
        return (
            base58.b58encode(verifying_key.to_string()),
            base58.b58encode(signing_key.to_string()),
        )

    @staticmethod
    def _generate_rsa_key_pair():
        key = RSA.generate(2048)
        return key.publickey().export_key(), key.export_key()

    @staticmethod
    def _validate_key_input_params(
        alias, signature_type, controller, priority_requirement, public_key, private_key
    ):
        if (public_key is None and private_key is not None) or (
            public_key is not None and private_key is None
        ):
            raise ValueError(
                "Both private key and public must be specified, or both must be unspecified"
            )

        if not re.match("^[a-z0-9-]{1,32}$", alias):
            raise ValueError(
                "Alias must not be more than 32 characters long and must contain only lower-case "
                "letters, digits and hyphens."
            )

        if signature_type not in (
            SignatureType.ECDSA.value,
            SignatureType.EdDSA.value,
            SignatureType.RSA.value,
        ):
            raise ValueError("Type must be a valid signature type.")

        if not re.match("^{}:[a-f0-9]{{64}}$".format(DID_METHOD_NAME), controller):
            raise ValueError("Controller must be a valid DID.")

        if priority_requirement is not None and priority_requirement < 0:
            raise ValueError("Priority requirement must be a non-negative integer.")


class ManagementKey(AbstractDIDKey):
    """
    A key used to sign updates for an existing DID.

    Attributes
    ----------
    alias: str
    priority: int
        A non-negative integer showing the hierarchical level of the key. Keys with lower priority override keys with
        higher priority.
    signature_type: SignatureType
    controller: str
    priority_requirement: int, optional
    public_key: str, optional
    private_key: str, optional
    """

    def __init__(
        self,
        alias,
        priority,
        signature_type,
        controller,
        priority_requirement=None,
        public_key=None,
        private_key=None,
    ):
        super().__init__(
            alias,
            signature_type,
            controller,
            priority_requirement,
            public_key,
            private_key,
        )

        if priority < 0:
            raise ValueError("Priority must be a non-negative integer.")

        self.priority = priority

    def __eq__(self, other):
        if self.__class__ is other.__class__:
            return super().__eq__(other) and self.priority == other.priority
        return NotImplemented

    def __hash__(self):
        return hash(
            (
                self.alias,
                self.priority,
                self.signature_type,
                self.controller,
                self.priority_requirement,
                self.public_key,
                self.private_key,
            )
        )


class DIDKey(AbstractDIDKey):
    """
    Application-level key, which can be used for authentication, signing requests, encryption, decryption, etc.

    Attributes
    ----------
    alias: str
    purpose: PurposeType[]
        A list of PurposeTypes showing what purpose(s) the key serves. (PublicKey, AuthenticationKey or both)
    signature_type: SignatureType
    controller: str
    priority_requirement: int, optional
    public_key: str, optional
    private_key: str, optional
    """

    def __init__(
        self,
        alias,
        purpose,
        signature_type,
        controller,
        priority_requirement=None,
        public_key=None,
        private_key=None,
    ):
        super().__init__(
            alias,
            signature_type,
            controller,
            priority_requirement,
            public_key,
            private_key,
        )

        for purpose_type in purpose:
            if purpose_type not in (
                PurposeType.PublicKey.value,
                PurposeType.AuthenticationKey.value,
            ):
                raise ValueError("Purpose must contain only valid PurposeTypes.")

        self.purpose = purpose

    def __eq__(self, other):
        if self.__class__ is other.__class__:
            return super().__eq__(other) and self.purpose == other.purpose
        return NotImplemented

    def __hash__(self):
        return hash(
            (
                self.alias,
                self.purpose,
                self.signature_type,
                self.controller,
                self.priority_requirement,
                self.public_key,
                self.private_key,
            )
        )
