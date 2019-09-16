import hashlib
import re

import base58
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from ecdsa import SigningKey, SECP256k1
import ed25519

from did.constants import DID_METHOD_NAME
from did.enums import DIDKeyPurpose, SignatureType

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

    def to_entry_dict(self, did):
        """
        Converts the object to a dictionary suitable for recording on-chain.

        Params
        ------
        did: str
            The DID with which this key is associated. Note that this can be different from the key controller.

        Returns
        -------
        dict
            Dictionary with `id`, `type`, `controller` and an optional `priorityRequirement` fields. In addition to
            those, there is one extra field for the public key: if the selected signature type is SignatureType.RSA,
            then this field is called `publicKeyPem`, otherwise it is called `publicKeyBase58`.

        """
        d = dict()

        d["id"] = self.full_id(did)
        d["type"] = "{}VerificationKey".format(self.signature_type)
        d["controller"] = self.controller
        if self.signature_type == SignatureType.RSA.value:
            d["publicKeyPem"] = str(self.public_key, "utf-8")
        else:
            d["publicKeyBase58"] = str(self.public_key, "utf-8")

        if self.priority_requirement is not None:
            d["priorityRequirement"] = self.priority_requirement

        return d

    def sign(self, msg, hash_f=hashlib.sha256):
        """
        Signs a message with the existing private key and signature type.

        The message is hashed before being signed, with the provided hash function. The default hash function used is
        SHA-256. Note that for RSA signature types, only SHA-256 hashing is currently supported.

        Parameters
        ----------
        msg: bytes
            The message to sign.
        hash_f: function, optional
            The hash function used to compute the digest of the message before signing it.

        Returns
        -------
        bytes
            The bytes of the signatures.
        """

        assert type(msg) is bytes, "Message must be supplied as bytes."

        if self.signature_type == SignatureType.ECDSA.value:
            return self.signing_key.sign_digest_deterministic(hash_f(msg).digest())
        elif self.signature_type == SignatureType.EdDSA.value:
            return self.signing_key.sign(hash_f(msg).digest())
        elif self.signature_type == SignatureType.RSA.value:
            return pkcs1_15.new(self.signing_key).sign(SHA256.new(msg))
        else:
            raise NotImplementedError(
                "Unsupported signature type: {}".format(self.signature_type)
            )

    def full_id(self, did):
        """
        Returns
        -------
        str
            The full id for the key, constituting of the DID_METHOD_NAME, the DID and the key alias.
        """
        return "{}#{}".format(did, self.alias)

    def _generate_ed_dsa_key_pair(self):
        self.signing_key, self.verifying_key = ed25519.create_keypair()
        return (
            base58.b58encode(self.verifying_key.to_bytes()),
            base58.b58encode(self.signing_key.to_bytes()),
        )

    def _generate_ec_dsa_key_pair(self):
        self.signing_key = SigningKey.generate(curve=SECP256k1)
        self.verifying_key = self.signing_key.get_verifying_key()
        return (
            base58.b58encode(self.verifying_key.to_string()),
            base58.b58encode(self.signing_key.to_string()),
        )

    def _generate_rsa_key_pair(self):
        self.signing_key = RSA.generate(2048)
        self.verifying_key = self.signing_key.publickey()

        return self.verifying_key.export_key(), self.signing_key.export_key()

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

    def to_entry_dict(self, did):
        d = super().to_entry_dict(did)
        d["priority"] = self.priority
        return d


class DIDKey(AbstractDIDKey):
    """
    Application-level key, which can be used for authentication, signing requests, encryption, decryption, etc.

    Attributes
    ----------
    alias: str
    purpose: DIDKeyPurpose or DIDKeyPurpose[]
        Shows what purpose(s) the key serves. (PublicKey, AuthenticationKey or both)
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

        if type(purpose) is list:
            purpose_l = purpose
        else:
            purpose_l = [purpose]

        for purpose_type in purpose_l:
            if purpose_type not in {
                DIDKeyPurpose.PublicKey.value,
                DIDKeyPurpose.AuthenticationKey.value,
            }:
                raise ValueError(
                    "Purpose must contain only valid DIDKeyPurpose values."
                )

        self.purpose = purpose_l

    def __eq__(self, other):
        if self.__class__ is other.__class__:
            return super().__eq__(other) and self.purpose == other.purpose
        return NotImplemented

    def __hash__(self):
        return hash(
            (
                self.alias,
                "".join(self.purpose),
                self.signature_type,
                self.controller,
                self.priority_requirement,
                self.public_key,
                self.private_key,
            )
        )

    def to_entry_dict(self, did):
        d = super().to_entry_dict(did)
        d["purpose"] = self.purpose
        return d
