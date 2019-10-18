import base58

from client.constants import ENTRY_SCHEMA_V100
from client.enums import DIDKeyPurpose, KeyType


class DIDKey(AbstractDIDKey):
    """
    Application-level key, which can be used for authentication, signing requests, encryption, decryption, etc.

    Attributes
    ----------
    alias: str
    purpose: DIDKeyPurpose or DIDKeyPurpose[]
        Shows what purpose(s) the key serves. (PublicKey, AuthenticationKey or both)
    key_type: KeyType
    controller: str
    priority_requirement: int, optional
    public_key: str, optional
    private_key: str, optional
    """

    def __init__(
        self,
        alias,
        purpose,
        key_type,
        controller,
        priority_requirement=None,
        public_key=None,
        private_key=None,
    ):
        super().__init__(
            alias, key_type, controller, priority_requirement, public_key, private_key
        )

        if type(purpose) is list:
            purpose_l = purpose
        else:
            purpose_l = [purpose]

        for purpose_type in purpose_l:
            if purpose_type not in {
                DIDKeyPurpose.PublicKey,
                DIDKeyPurpose.AuthenticationKey,
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
                "".join(map(lambda x: x.value, self.purpose)),
                self.key_type,
                self.controller,
                self.priority_requirement,
                self.public_key,
                self.private_key,
            )
        )

    def __repr__(self):
        public_key = str(self.public_key, "utf-8")
        if self.key_type == KeyType.RSA:
            public_key = AbstractDIDKey._minify_rsa_public_key(public_key)

        return (
            "<{0}.{1} (alias={2}, purpose={3}, key_type={4},"
            " controller={5}, priority_requirement={6}, public_key={7}, private_key=({8}))>".format(
                self.__module__,
                type(self).__name__,
                self.alias,
                self.purpose,
                self.key_type,
                self.controller,
                self.priority_requirement,
                public_key,
                "hidden" if self.private_key is not None else "not set",
            )
        )

    def to_entry_dict(self, did, version=ENTRY_SCHEMA_V100):
        if version == ENTRY_SCHEMA_V100:
            d = super().to_entry_dict(did)
            d["purpose"] = list(map(lambda x: x.value, self.purpose))
            return d
        else:
            raise NotImplementedError("Unknown schema version: {}".format(version))

    @staticmethod
    def from_entry_dict(entry_dict, version=ENTRY_SCHEMA_V100):
        k = AbstractDIDKey.from_entry_dict(entry_dict, version)
        return DIDKey(
            alias=k.alias,
            purpose=list(map(DIDKeyPurpose.from_str, entry_dict.get("purpose"))),
            key_type=k.key_type,
            controller=k.controller,
            priority_requirement=k.priority_requirement,
            public_key=base58.b58decode(k.public_key)
            if k.public_key is not None and k.key_type != KeyType.RSA
            else k.public_key,
            private_key=base58.b58decode(k.private_key)
            if k.private_key is not None and k.key_type != KeyType.RSA
            else k.private_key,
        )
