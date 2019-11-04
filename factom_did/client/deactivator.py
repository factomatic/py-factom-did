import hashlib
import operator as op

from factom_did.client.constants import ENTRY_SCHEMA_V100
from factom_did.client.enums import EntryType


class DIDDeactivator:
    def __init__(self, did):
        self.did = did
        self.signing_key = sorted(
            self.did.management_keys, key=op.attrgetter("priority")
        )[0]

        assert (
            self.signing_key.priority == 0
        ), "Deactivation of a DID requires the availability of a management key with priority 0."

    def export_entry_data(self):
        data_to_sign = "".join(
            [
                EntryType.VersionUpgrade.value,
                ENTRY_SCHEMA_V100,
                self.signing_key.full_id(self.did.id),
            ]
        )
        signature = self.signing_key.sign(
            hashlib.sha256(data_to_sign.encode("utf-8")).digest()
        )

        ext_ids = [
            EntryType.VersionUpgrade.value.encode("utf-8"),
            ENTRY_SCHEMA_V100.encode("utf-8"),
            self.signing_key.full_id(self.did.id).encode("utf-8"),
            signature,
        ]

        # The content of the DIDDeactivation entry is empty
        return {"ext_ids": ext_ids, "content": b""}
