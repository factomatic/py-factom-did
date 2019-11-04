import pytest

from factom_did.client.constants import ENTRY_SCHEMA_V100
from factom_did.client.did import DID, DIDKeyPurpose


@pytest.fixture
def did():
    return (
        DID()
        .management_key("man-key1", 0)
        .did_key("did-key1", DIDKeyPurpose.AuthenticationKey, priority_requirement=2)
        .service("gmail-service", "email-service", "https://gmail.com", 2)
    )


@pytest.fixture
def did_2():
    return (
        DID()
        .management_key("man-key1", 1)
        .did_key("did-key1", DIDKeyPurpose.AuthenticationKey, priority_requirement=2)
        .service("gmail-service", "email-service", "https://gmail.com", 2)
    )


class TestDeactivation:
    def test_deactivation_with_no_management_key(self):
        with pytest.raises(RuntimeError):
            DID().deactivate()

    def test_deactivation_with_no_management_key_of_priority_zero(self, did_2):
        with pytest.raises(AssertionError):
            did_2.deactivate()

    def test_successful_deactivation(self, did):
        entry = did.deactivate().export_entry_data()
        ext_ids = entry["ext_ids"]
        content = entry["content"]

        assert ext_ids[0] == "DIDDeactivation".encode("utf-8")
        assert ext_ids[1] == ENTRY_SCHEMA_V100.encode("utf-8")
        assert ext_ids[2] == "{}#{}".format(did.id, "man-key1").encode("utf-8")
        assert len(ext_ids) == 4
        assert content == b""
