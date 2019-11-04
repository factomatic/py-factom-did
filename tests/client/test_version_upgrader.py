import json

import pytest

from factom_did.client.constants import ENTRY_SCHEMA_V100
from factom_did.client.did import DID, DIDKeyPurpose


@pytest.fixture
def did():
    return (
        DID()
        .management_key("man-key1", 0)
        .management_key("man-key2", 2)
        .did_key("did-key1", DIDKeyPurpose.AuthenticationKey, priority_requirement=2)
        .service("gmail-service", "email-service", "https://gmail.com", 2)
    )


class TestMethodSpecVersionUpgrade:
    def test_upgrade_with_no_management_key(self):
        with pytest.raises(RuntimeError):
            DID().method_spec_version_upgrade("1.0.0")

    def test_downgrade(self, did):
        with pytest.raises(ValueError):
            did.method_spec_version_upgrade("0.1.0")

    def test_successful_upgrade(self, did):
        entry = did.method_spec_version_upgrade("1.0.0").export_entry_data()
        ext_ids = entry["ext_ids"]
        content = json.loads(entry["content"])

        assert ext_ids[0] == "DIDMethodVersionUpgrade".encode("utf-8")
        assert ext_ids[1] == ENTRY_SCHEMA_V100.encode("utf-8")
        assert ext_ids[2] == "{}#{}".format(did.id, "man-key2").encode("utf-8")
        assert len(ext_ids) == 4
        assert len(content) == 1
        assert content["didMethodVersion"] == "1.0.0"
