import hashlib
import json
import operator as op
from packaging import version

from factom_did.client.constants import ENTRY_SCHEMA_V100
from factom_did.client.enums import EntryType


class DIDVersionUpgrader:
    def __init__(self, did, new_spec_version):
        if version.parse(did.spec_version) >= version.parse(new_spec_version):
            raise ValueError("New version must be an upgrade on old version")
        self.did = did
        self.new_spec_version = new_spec_version

    def export_entry_data(self):
        # Sign with the management key with least priority
        signing_key = sorted(
            self.did.management_keys, key=op.attrgetter("priority"), reverse=True
        )[0]

        entry_content = json.dumps({"didMethodVersion": self.new_spec_version}).replace(
            " ", ""
        )
        data_to_sign = "".join(
            [
                EntryType.VersionUpgrade.value,
                ENTRY_SCHEMA_V100,
                signing_key.full_id(self.did.id),
                entry_content,
            ]
        )
        signature = signing_key.sign(
            hashlib.sha256(data_to_sign.encode("utf-8")).digest()
        )

        ext_ids = [
            EntryType.VersionUpgrade.value.encode("utf-8"),
            ENTRY_SCHEMA_V100.encode("utf-8"),
            signing_key.full_id(self.did.id).encode("utf-8"),
            signature,
        ]

        return {"ext_ids": ext_ids, "content": entry_content.encode("utf-8")}
