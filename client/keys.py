import hashlib
import re

import base58
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
import ecdsa
from ecdsa.curves import SECP256k1
import ed25519

from client.constants import DID_METHOD_NAME
from client.enums import DIDKeyPurpose, SignatureType

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
    public_key: bytes or str, optional
        The public key.
    private_key: bytes or str, optional
        The private key.
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

        self._derive_signing_and_verifying_key(public_key, private_key)

        if self.signature_type == SignatureType.EdDSA.value:
            self.public_key = base58.b58encode(self.verifying_key.to_bytes())
            self.private_key = base58.b58encode(self.signing_key.to_bytes())
        elif self.signature_type == SignatureType.ECDSA.value:
            self.public_key = base58.b58encode(self.verifying_key.to_string())
            self.private_key = base58.b58encode(self.signing_key.to_string())
        elif self.signature_type == SignatureType.RSA.value:
            self.public_key = self.verifying_key.export_key()
            self.private_key = self.signing_key.export_key(
                format="PEM", passphrase=None, pkcs=8
            )
        else:
            raise NotImplementedError(
                "Unsupported signature type: {}".format(self.signature_type)
            )

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
            self._generate_ed_dsa_key_pair()
        elif self.signature_type == SignatureType.ECDSA.value:
            self._generate_ec_dsa_key_pair()
        elif self.signature_type == SignatureType.RSA.value:
            self._generate_rsa_key_pair()
        else:
            raise NotImplementedError(
                "Unsupported signature type: {}".format(self.signature_type)
            )

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

    def rotate(self):
        """
            Generates new key pair for the key.
        """

        self.generate_key_pair()

        if self.signature_type == SignatureType.EdDSA.value:
            self.public_key = base58.b58encode(self.verifying_key.to_bytes())
            self.private_key = base58.b58encode(self.signing_key.to_bytes())
        elif self.signature_type == SignatureType.ECDSA.value:
            self.public_key = base58.b58encode(self.verifying_key.to_string())
            self.private_key = base58.b58encode(self.signing_key.to_string())
        elif self.signature_type == SignatureType.RSA.value:
            self.public_key = self.verifying_key.export_key()
            self.private_key = self.signing_key.export_key(
                format="PEM", passphrase=None, pkcs=8
            )

    def sign(self, message, hash_f=hashlib.sha256):
        """
        Signs a message with the existing private key and signature type.

        The message is hashed before being signed, with the provided hash function. The default hash function used is
        SHA-256. Note that for RSA signature types, only SHA-256 hashing is currently supported.

        Parameters
        ----------
        message: bytes
            The message to sign.
        hash_f: function, optional
            The hash function used to compute the digest of the message before signing it.

        Returns
        -------
        bytes
            The bytes of the signatures.

        Raises
        ------
        NotImplementedError
            If the signature type is not supported.
        """

        assert type(message) is bytes, "Message must be supplied as bytes."

        if self.signature_type == SignatureType.ECDSA.value:
            return self.signing_key.sign_digest(hash_f(message).digest())
        elif self.signature_type == SignatureType.EdDSA.value:
            return self.signing_key.sign(hash_f(message).digest())
        elif self.signature_type == SignatureType.RSA.value:
            return pkcs1_15.new(self.signing_key).sign(SHA256.new(message))
        else:
            raise NotImplementedError(
                "Unsupported signature type: {}".format(self.signature_type)
            )

    def verify(self, message, signature, hash_f=hashlib.sha256):
        """
        Verifies the signature of the given message

        Parameters
        ----------
        message: bytes
            The (allegedly) signed message.
        signature: bytes
            The signature to verify.
        hash_f: function, optional
            The hash function used to compute the digest of the message.

        Returns
        -------
        bool
            True if the signature is successfully verified, False otherwise.

        Raises
        ------
        NotImplementedError
            If the signature type is not supported.
        """
        from ecdsa.keys import BadSignatureError as ECDSABadSignatureError
        from ed25519 import BadSignatureError as Ed25519BadSignatureError

        assert type(message) is bytes, "Message must be supplied as bytes."
        assert type(signature) is bytes, "Signature must be supplied as bytes."

        if self.signature_type == SignatureType.ECDSA.value:
            try:
                return self.verifying_key.verify_digest(
                    signature, hash_f(message).digest()
                )
            except ECDSABadSignatureError:
                return False
        elif self.signature_type == SignatureType.EdDSA.value:
            try:
                self.verifying_key.verify(signature, hash_f(message).digest())
            except Ed25519BadSignatureError:
                return False
            else:
                return True
        elif self.signature_type == SignatureType.RSA.value:
            try:
                pkcs1_15.new(self.verifying_key).verify(SHA256.new(message), signature)
            except ValueError:
                return False
            else:
                return True
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

    def _generate_ec_dsa_key_pair(self):
        self.signing_key = ecdsa.SigningKey.generate(curve=SECP256k1)
        self.verifying_key = self.signing_key.get_verifying_key()

    def _generate_rsa_key_pair(self):
        self.signing_key = RSA.generate(2048)
        self.verifying_key = self.signing_key.publickey()

    def _derive_signing_and_verifying_key(self, public_key, private_key):
        if public_key is None and private_key is None:
            self.generate_key_pair()
            return

        # At this point, private_key is not None, due to the check above and the one in
        # _validate_key_input_params, so we can proceed with the derivation of the
        # signing key object based on the signature type
        if self.signature_type == SignatureType.EdDSA.value:
            try:
                self.signing_key = ed25519.SigningKey(private_key)
                self.verifying_key = self.signing_key.get_verifying_key()
            except ValueError:
                raise ValueError("Invalid EdDSA private key. Must be a 32-byte seed.")
        elif self.signature_type == SignatureType.ECDSA.value:
            try:
                self.signing_key = ecdsa.SigningKey.from_string(
                    private_key, curve=SECP256k1
                )
                self.verifying_key = self.signing_key.get_verifying_key()
            except (AssertionError, ValueError):
                raise ValueError(
                    "Invalid ECDSA private key. Must be a 32-byte secret exponent."
                )
        elif self.signature_type == SignatureType.RSA.value:
            # Raise the default exception in case this fails, as it's informative enough
            self.signing_key = RSA.import_key(private_key)
            self.verifying_key = self.signing_key.publickey()
        else:
            raise NotImplementedError(
                "Unsupported signature type: {}".format(self.signature_type)
            )

        # If a public key is provided in conjunction with the private key, validate that
        # the public key matches the generated verification key, otherwise raise an
        # exception
        if public_key is not None:
            non_matching_public_key_msg = (
                "The provided public key does not match the one derived "
                "from the provided private key"
            )
            if self.signature_type == SignatureType.EdDSA.value:
                if type(public_key) is bytes:
                    assert (
                        self.verifying_key.to_bytes() == public_key
                    ), non_matching_public_key_msg
                else:
                    assert (
                        self.verifying_key.to_bytes().decode() == public_key
                    ), non_matching_public_key_msg
            elif self.signature_type == SignatureType.ECDSA.value:
                if type(public_key) is bytes:
                    assert (
                        self.verifying_key.to_string() == public_key
                    ), non_matching_public_key_msg
                else:
                    assert (
                        self.verifying_key.to_string().decode() == public_key
                    ), non_matching_public_key_msg
            else:
                # This must be an RSA key, as if it were anything else a NotImplementedError
                # would have been raised above
                assert (
                    RSA.import_key(public_key) == self.verifying_key
                ), non_matching_public_key_msg

    @staticmethod
    def _minify_rsa_public_key(public_key):
        start_index = public_key.find("\n") + 1
        end_index = public_key.rfind("\n")

        return "{0}...{1}".format(
            public_key[start_index : start_index + 20],
            public_key[end_index - 8 : end_index],
        )

    @staticmethod
    def _validate_key_input_params(
        alias, signature_type, controller, priority_requirement, public_key, private_key
    ):
        if public_key is not None and private_key is None:
            raise ValueError(
                "Public key specified without a corresponding private key."
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

    def __repr__(self):
        public_key = str(self.public_key, "utf-8")
        if self.signature_type == SignatureType.RSA.value:
            public_key = AbstractDIDKey._minify_rsa_public_key(public_key)

        return (
            "<{0}.{1} (alias={2}, priority={3}, signature_type={4},"
            " controller={5}, priority_requirement={6}, public_key={7}, private_key=(hidden))>".format(
                self.__module__,
                type(self).__name__,
                self.alias,
                self.priority,
                self.signature_type,
                self.controller,
                self.priority_requirement,
                public_key,
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

    def __repr__(self):
        public_key = str(self.public_key, "utf-8")
        if self.signature_type == SignatureType.RSA.value:
            public_key = AbstractDIDKey._minify_rsa_public_key(public_key)

        return (
            "<{0}.{1} (alias={2}, purpose={3}, signature_type={4},"
            " controller={5}, priority_requirement={6}, public_key={7}, private_key=(hidden))>".format(
                self.__module__,
                type(self).__name__,
                self.alias,
                self.purpose,
                self.signature_type,
                self.controller,
                self.priority_requirement,
                public_key,
            )
        )

    def to_entry_dict(self, did):
        d = super().to_entry_dict(did)
        d["purpose"] = self.purpose
        return d
