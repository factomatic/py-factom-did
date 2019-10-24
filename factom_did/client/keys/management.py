import base58

from factom_did.client.constants import ENTRY_SCHEMA_V100
from factom_did.client.enums import KeyType
from factom_did.client.keys.abstract import AbstractDIDKey


class ManagementKey(AbstractDIDKey):
    """
    A key used to sign updates for an existing DID.

    Attributes
    ----------
    alias: str
    priority: int
        A non-negative integer showing the hierarchical level of the key. Keys with lower priority override keys with
        higher priority.
    key_type: KeyType
    controller: str
    priority_requirement: int, optional
    public_key: str, optional
    private_key: str, optional
    """

    def __init__(
        self,
        alias,
        priority,
        key_type,
        controller,
        priority_requirement=None,
        public_key=None,
        private_key=None,
    ):
        super().__init__(
            alias, key_type, controller, priority_requirement, public_key, private_key
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
                self.key_type,
                self.controller,
                self.priority_requirement,
                self.public_key,
                self.private_key,
            )
        )

    def __repr__(self):
        return (
            "<{}.{}(alias={}, priority={}, key_type={}, controller={}, "
            "priority_requirement={})>".format(
                self.__module__,
                type(self).__name__,
                self.alias,
                self.priority,
                self.underlying,
                self.controller,
                self.priority_requirement,
            )
        )

    def to_entry_dict(self, did, version=ENTRY_SCHEMA_V100):
        if version == ENTRY_SCHEMA_V100:
            d = super().to_entry_dict(did)
            d["priority"] = self.priority
            return d
        else:
            raise NotImplementedError("Unknown schema version: {}".format(version))

    @staticmethod
    def from_entry_dict(entry_dict, version=ENTRY_SCHEMA_V100):
        if version == ENTRY_SCHEMA_V100:
            return ManagementKey(
                alias=entry_dict["id"].split("#")[-1],
                priority=entry_dict["priority"],
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
