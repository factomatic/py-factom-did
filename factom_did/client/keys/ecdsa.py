import hashlib

import base58
import ecdsa
from ecdsa.curves import SECP256k1


class ECDSASecp256k1Key:
    """
    Representation of an ECDSASecp256k1 key. Instances of this class allow signing of messages and signature
    verification, as well as key creation and derivation of a public key from a private key.
    """

    ON_CHAIN_PUB_KEY_NAME = "publicKeyBase58"

    def __init__(self, public_key=None, private_key=None):
        """
        Creates an ECDSASecp256k1Key object.

        If both the public and private keys are not provided, it will generate a new key pair.
        If both are provided, it will check that the public key corresponds to the private key.
        If only a private key is provided, it will derive the public key.
        If only a public key is provided, signing will not work, but signature verification is possible.

        Parameters
        ----------
        public_key: str or bytes (optional)
            The public key to use when creating the object.
        private_key: str or bytes (optional)

        Raises
        ------
        ValueError
            If a private or public key is provided in an invalid format
        AssertionError
            If the public and private keys provided do not correspond to each other
        """
        if public_key is not None and type(public_key) is not bytes:
            raise ValueError("public_key must be bytes")
        if private_key is not None and type(private_key) is not bytes:
            raise ValueError("private_key must be bytes")
        # Instantiate the signing and verifying key _objects_ from the provided private and public key _values_
        self._derive_signing_and_verifying_key(public_key, private_key)

    def __repr__(self):
        return "<{}.{}(public_key={}, private_key=({}))>".format(
            self.__module__,
            type(self).__name__,
            base58.b58encode(self.verifying_key.to_string()).decode("utf-8"),
            "hidden" if self.signing_key is not None else "not set",
        )

    @property
    def public_key(self):
        return self.verifying_key.to_string()

    @property
    def private_key(self):
        return self.signing_key.to_string() if self.signing_key is not None else None

    def sign(self, message, hash_f=hashlib.sha256):
        """
        Signs a message with the existing private key and signature type.

        The message is hashed before being signed, with the provided hash function. The default hash function used is
        SHA-256.

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
        AssertionError
            If the supplied message is not bytes, or if a private key has not been specified.
        """
        assert type(message) is bytes, "Message must be bytes."
        assert self.signing_key is not None, "Signing is not set."

        return self.signing_key.sign_digest(hash_f(message).digest())

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
        """
        from ecdsa.keys import BadSignatureError

        assert type(message) is bytes, "Message must be bytes"
        assert type(signature) is bytes, "Signature must be bytes"

        try:
            return self.verifying_key.verify_digest(signature, hash_f(message).digest())
        except BadSignatureError:
            return False

    def get_public_key_on_chain_repr(self):
        return self.ON_CHAIN_PUB_KEY_NAME, base58.b58encode(self.public_key).decode()

    def _derive_signing_and_verifying_key(self, public_key, private_key):
        # If neither the public, nor the private key is set, generate the key pair and return
        if public_key is None and private_key is None:
            self.signing_key = ecdsa.SigningKey.generate(curve=SECP256k1)
            self.verifying_key = self.signing_key.get_verifying_key()
            return

        # If both the public key and the private key are set, attempt to construct the objects, verify
        # that the keys are matching and return
        if public_key is not None and private_key is not None:
            try:
                self.signing_key = ecdsa.SigningKey.from_string(
                    private_key, curve=SECP256k1
                )
            except (AssertionError, ValueError):
                raise ValueError(
                    "Invalid ECDSA private key. Must be a 32-byte secret exponent."
                )
            self.verifying_key = self.signing_key.get_verifying_key()
            non_matching_public_key_msg = (
                "The provided public key does not match the one derived "
                "from the provided private key"
            )
            assert (
                self.verifying_key.to_string() == public_key
            ), non_matching_public_key_msg
            return

        # At this point, either only the public key is set or only the private key is set

        if public_key is not None:
            try:
                self.signing_key = None
                self.verifying_key = ecdsa.VerifyingKey.from_string(
                    public_key, curve=SECP256k1
                )
            except (AssertionError, ValueError):
                raise ValueError(
                    "Invalid ECDSA public key. Must be a 64-byte encoded SECP256k1 curve point."
                )
        else:
            # Private key is not None
            try:
                self.signing_key = ecdsa.SigningKey.from_string(
                    private_key, curve=SECP256k1
                )
                self.verifying_key = self.signing_key.get_verifying_key()
            except (AssertionError, ValueError):
                raise ValueError(
                    "Invalid ECDSA private key. Must be a 32-byte secret exponent."
                )
