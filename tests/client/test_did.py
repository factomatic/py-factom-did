import json
import pytest
import re

import base58

from factom_did.client.constants import (
    ENTRY_SCHEMA_V100,
    DID_METHOD_SPEC_V020,
    DID_METHOD_NAME,
)
from factom_did.client.did import DID, DIDKeyPurpose, KeyType
from factom_did.client.enums import EntryType, Network


@pytest.fixture
def did():
    return DID()


class TestDidValidator:
    def test_did_validator(self):
        assert DID.is_valid_did("") is False
        assert DID.is_valid_did("asdf") is False
        assert (
            DID.is_valid_did(
                "did:factom:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )
            is True
        )
        assert (
            DID.is_valid_did(
                "did:factom:mainnet:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )
            is True
        )
        assert (
            DID.is_valid_did(
                "did:factom:Mainnet:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )
            is False
        )
        assert (
            DID.is_valid_did(
                "did:factom:testnet:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )
            is True
        )
        assert (
            DID.is_valid_did(
                "did:factom:Testnet:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )
            is False
        )
        assert (
            DID.is_valid_did(
                "did:factom:z3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )
            is False
        )
        assert (
            DID.is_valid_did(
                "did:factom:E3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )
            is False
        )


class TestGetChain:
    def test_get_chain_with_automatically_created_did(self, did):
        assert re.match("[0-9a-f]{64}", did.get_chain()) is not None

    def test_get_chain_with_provided_did(self):
        did = DID(
            did="did:factom:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert (
            did.get_chain()
            == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

        did = DID(
            did="did:factom:mainnet:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert (
            did.get_chain()
            == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )


class TestEmptyDid:
    def test_generating_new_empty_did(self, did):
        assert re.search("^{}:[a-f0-9]{{64}}$".format(DID_METHOD_NAME), did.id)
        assert 32 == len(did.nonce)
        assert [] == did.management_keys
        assert [] == did.did_keys
        assert [] == did.services
        assert set() == did.used_key_aliases
        assert set() == did.used_service_aliases
        assert Network.Unspecified == did.network

    def test__repr__method(self, did):
        expected__repr__method_output = "<{0}.{1} (management_keys={2}, did_keys={3}, services={4})>".format(
            DID.__module__,
            DID.__name__,
            len(did.management_keys),
            len(did.did_keys),
            len(did.services),
        )

        assert str(did) == expected__repr__method_output


class TestExportEntryData:
    def test_export_entry_data_returns_correct_ext_ids(self, did):
        did.management_key("my-management-key", 0)
        entry_data = did.export_entry_data()

        ext_ids = entry_data["ext_ids"]
        assert EntryType.Create.value == ext_ids[0].decode()
        assert ENTRY_SCHEMA_V100 == ext_ids[1].decode()
        assert did.nonce == ext_ids[2]

    def test_export_entry_data_with_management_key(self, did):
        key_alias = "my-management-key"
        key_priority = 0
        did.management_key(key_alias, key_priority)
        entry_data = did.export_entry_data()

        content = json.loads(entry_data["content"])
        assert DID_METHOD_SPEC_V020 == content["didMethodVersion"]

        management_keys = content["managementKey"]
        assert 1 == len(management_keys)
        with pytest.raises(KeyError):
            content["didKey"]
        with pytest.raises(KeyError):
            content["service"]

        management_key_1 = management_keys[0]
        assert "{}#{}".format(did.id, key_alias) == management_key_1["id"]
        assert KeyType.EdDSA.value == management_key_1["type"]
        assert did.id == management_key_1["controller"]
        assert (
            str(base58.b58encode(did.management_keys[0].public_key), "utf8")
            == management_key_1["publicKeyBase58"]
        )
        assert key_priority == management_key_1["priority"]

    def test_export_entry_data_with_did_key_and_service(self, did):
        did_key_alias = "my-public-key"
        did_key_purpose = [DIDKeyPurpose.PublicKey]
        did_key_type = KeyType.RSA
        did_key_controller = "{}:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b8005".format(
            DID_METHOD_NAME
        )
        did_key_priority_requirement = 1
        service_alias = "my-photo-service"
        service_type = "PhotoStreamService"
        service_endpoint = "https://myphoto.com"
        service_priority_requirement = 2
        did.mainnet().management_key("my-management-key-1", 0).management_key(
            "my-management-key-2", 2
        ).did_key(
            did_key_alias,
            did_key_purpose,
            did_key_type,
            did_key_controller,
            did_key_priority_requirement,
        ).service(
            service_alias, service_type, service_endpoint, service_priority_requirement
        )
        entry_data = did.export_entry_data()
        content = json.loads(entry_data["content"])

        management_keys = content["managementKey"]
        did_keys = content["didKey"]
        services = content["service"]
        assert 2 == len(management_keys)
        assert 1 == len(did_keys)
        assert 1 == len(services)

        did_key_1 = did_keys[0]
        assert "{}#{}".format(did.id, did_key_alias) == did_key_1["id"]
        assert did_key_type.value == did_key_1["type"]
        assert did_key_controller == did_key_1["controller"]
        assert str(did.did_keys[0].public_key, "utf8") == did_key_1["publicKeyPem"]
        assert list(map(lambda x: x.value, did_key_purpose)) == did_key_1["purpose"]
        assert did_key_priority_requirement == did_key_1["priorityRequirement"]

        service_1 = services[0]
        assert "{}#{}".format(did.id, service_alias) == service_1["id"]
        assert service_type == service_1["type"]
        assert service_endpoint == service_1["serviceEndpoint"]
        assert service_priority_requirement == service_1["priorityRequirement"]

    def test_exceed_entry_size_throws_error(self, did):
        for x in range(0, 35):
            did.management_key("management-key-{}".format(x), 0)

        with pytest.raises(RuntimeError):
            did.export_entry_data()

    def test_export_without_management_key_throws_error(self, did):
        with pytest.raises(ValueError):
            did.export_entry_data()
