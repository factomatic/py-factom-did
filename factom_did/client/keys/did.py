import base58

from factom_did.client.constants import ENTRY_SCHEMA_V100
from factom_did.client.enums import DIDKeyPurpose, KeyType
from factom_did.client.keys.abstract import AbstractDIDKey


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

        assert len(set(purpose_l)) == len(purpose_l) and (
            len(purpose_l) == 1 or len(purpose_l) == 2
        ), "Purpose must contain one or both of {} and {} without repeated values".format(
            DIDKeyPurpose.PublicKey.value, DIDKeyPurpose.AuthenticationKey.value
        )

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
        return (
            "<{}.{}(alias={}, purpose={}, key_type={}, controller={}, "
            "priority_requirement={})>".format(
                self.__module__,
                type(self).__name__,
                self.alias,
                self.purpose,
                self.underlying,
                self.controller,
                self.priority_requirement,
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
        if version == ENTRY_SCHEMA_V100:
            return DIDKey(
                alias=entry_dict["id"].split("#")[-1],
                purpose=list(map(DIDKeyPurpose.from_str, entry_dict.get("purpose"))),
                key_type=KeyType.from_str(entry_dict["type"]),
                controller=entry_dict["controller"],
                priority_requirement=entry_dict.get("priorityRequirement"),
                public_key=base58.b58decode(entry_dict["publicKeyBase58"])
                if "publicKeyBase58" in entry_dict
                else entry_dict["publicKeyPem"],
                private_key=None,
            )
        else:
            raise NotImplementedError("Unknown schema version: {}".format(version))
