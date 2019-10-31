import base58

from factom_did.client.constants import ENTRY_SCHEMA_V100
from factom_did.client.enums import KeyType
from factom_did.client.keys.ecdsa import ECDSASecp256k1Key
from factom_did.client.keys.eddsa import Ed25519Key
from factom_did.client.keys.rsa import RSAKey
from factom_did.client.validators import (
    validate_alias,
    validate_did,
    validate_key_type,
    validate_priority_requirement,
)


class AbstractDIDKey:
    """
    Represents the common fields and functionality in a ManagementKey and a DidKey.

    Attributes
    ----------
    alias: str
        A human-readable nickname for the key.
    key_type: KeyType
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
        key_type,
        controller,
        priority_requirement,
        public_key=None,
        private_key=None,
    ):

        self._validate_key_input_params(
            alias, key_type, controller, priority_requirement
        )

        self.alias = alias
        self.key_type = key_type
        self.controller = controller
        self.priority_requirement = priority_requirement

        if self.key_type == KeyType.EdDSA:
            self.underlying = Ed25519Key(public_key, private_key)
        elif self.key_type == KeyType.ECDSA:
            self.underlying = ECDSASecp256k1Key(public_key, private_key)
        elif self.key_type == KeyType.RSA:
            self.underlying = RSAKey(public_key, private_key)
        else:
            raise NotImplementedError(
                "Unsupported signature type: {}".format(self.key_type.value)
            )

    def __eq__(self, other):
        if self.__class__ is other.__class__:
            return (
                self.alias,
                self.key_type,
                self.controller,
                self.priority_requirement,
                self.public_key,
                self.private_key,
            ) == (
                other.alias,
                other.key_type,
                other.controller,
                other.priority_requirement,
                other.public_key,
                other.private_key,
            )
        return NotImplemented

    @property
    def verifying_key(self):
        return self.underlying.verifying_key

    @property
    def signing_key(self):
        return self.underlying.signing_key

    @property
    def public_key(self):
        return self.underlying.public_key

    @property
    def private_key(self):
        return self.underlying.private_key

    def sign(self, message, hash_f=None):
        return (
            self.underlying.sign(message, hash_f)
            if hash_f is not None
            else self.underlying.sign(message)
        )

    def verify(self, message, signature, hash_f=None):
        return (
            self.underlying.verify(message, signature, hash_f)
            if hash_f is not None
            else self.underlying.verify(message, signature)
        )

    def to_entry_dict(self, did, version=ENTRY_SCHEMA_V100):
        """
        Converts the object to a dictionary suitable for recording on-chain.

        Parameters
        ----------
        did: str
            The DID with which this key is associated. Note that this can be different from the key controller.
        version: str
            The entry schema version

        Returns
        -------
        dict
            Dictionary with `id`, `type`, `controller` and an optional `priorityRequirement` fields. In addition to
            those, there is one extra field for the public key: if the selected signature type is SignatureType.RSA,
            then this field is called `publicKeyPem`, otherwise it is called `publicKeyBase58`.

        """
        if version == ENTRY_SCHEMA_V100:
            d = dict()

            d["id"] = self.full_id(did)
            d["type"] = self.key_type.value
            d["controller"] = self.controller
            (key, value) = self.underlying.get_public_key_on_chain_repr()
            d[key] = value

            if self.priority_requirement is not None:
                d["priorityRequirement"] = self.priority_requirement

            return d
        else:
            raise NotImplementedError("Unknown schema version: {}".format(version))

    @staticmethod
    def from_entry_dict(entry_dict, version=ENTRY_SCHEMA_V100):
        """
        Creates an AbstractDIDKey object from an on-chain entry

        Parameters
        ----------
        entry_dict: dict
            The on-chain entry, represented as a Python dictionary
        version: str
            The entry schema version

        Returns
        -------
        AbstractDIDKey

        Raises
        ------
        NotImplementedError
            If the supplied version is not supported
        """
        if version == ENTRY_SCHEMA_V100:
            return AbstractDIDKey(
                alias=entry_dict.get("id", "").split("#")[-1],
                key_type=KeyType.from_str(entry_dict.get("type")),
                controller=entry_dict.get("controller"),
                priority_requirement=entry_dict.get("priorityRequirement"),
                public_key=base58.b58decode(entry_dict["publicKeyBase58"])
                if "publicKeyBase58" in entry_dict
                else entry_dict.get("publicKeyPem"),
            )
        else:
            raise NotImplementedError("Unknown schema version: {}".format(version))

    def rotate(self):
        """
        Generates new key pair for the key.
        """
        assert self.signing_key is not None, "Private key must be set"
        self.underlying = self.underlying.__class__()

    def full_id(self, did):
        """
        Constructs the full ID of the key.

        Parameters
        ----------
        did: str

        Returns
        -------
        str
            The full id for the key, constituting of the DID_METHOD_NAME, the network, the chain ID and the key alias.
        """
        return "{}#{}".format(did, self.alias)

    @staticmethod
    def _validate_key_input_params(alias, key_type, controller, priority_requirement):
        validate_alias(alias)
        validate_key_type(key_type)
        validate_did(controller)
        validate_priority_requirement(priority_requirement)
