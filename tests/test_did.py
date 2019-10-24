import json
import pytest
import re

import base58

from client.constants import ENTRY_SCHEMA_V100, DID_METHOD_SPEC_V020, DID_METHOD_NAME
from client.did import DID, KeyType, DIDKeyPurpose
from client.enums import EntryType
from client.keys.abstract import AbstractDIDKey
from client.keys.did import DIDKey
from client.keys.management import ManagementKey
from client.keys.rsa import RSAKey
from client.service import Service


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


class TestMinifyRSAPublicKey:
    def test_minify_rsa_public_key(self):
        rsa_key = RSAKey()
        minified_public_key = rsa_key._minify_public_key()
        assert len(minified_public_key) < len(rsa_key.public_key)
        assert len(minified_public_key) == 31


class TestEmptyDid:
    def test_generating_new_empty_did(self, did):
        assert re.search("^{}:[a-f0-9]{{64}}$".format(DID_METHOD_NAME), did.id)
        assert 32 == len(did.nonce)
        assert [] == did.management_keys
        assert [] == did.did_keys
        assert [] == did.services
        assert set() == did.used_key_aliases
        assert set() == did.used_service_aliases

    def test__repr__method(self, did):
        expected__repr__method_output = "<{0}.{1} (management_keys={2}, did_keys={3}, services={4})>".format(
            DID.__module__,
            DID.__name__,
            len(did.management_keys),
            len(did.did_keys),
            len(did.services),
        )

        assert str(did) == expected__repr__method_output


class TestManagementKeys:
    def test_add_management_keys(self, did):
        management_key_1_alias = "management-key-1"
        management_key_1_priority = 1
        did.management_key(management_key_1_alias, management_key_1_priority)
        generated_management_key_1 = did.management_keys[0]

        assert management_key_1_alias == generated_management_key_1.alias
        assert management_key_1_priority == generated_management_key_1.priority
        assert KeyType.EdDSA == generated_management_key_1.key_type
        assert did.id == generated_management_key_1.controller
        assert generated_management_key_1.public_key is not None
        assert generated_management_key_1.private_key is not None

        management_key_2_alias = "management-key-2"
        management_key_2_priority = 2
        management_key_2_type = KeyType.ECDSA
        management_key_2_controller = "{}:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b8005".format(
            DID_METHOD_NAME
        )

        did.management_key(
            management_key_2_alias,
            management_key_2_priority,
            management_key_2_type,
            management_key_2_controller,
        )
        generated_management_key_2 = did.management_keys[1]

        assert management_key_2_alias == generated_management_key_2.alias
        assert management_key_2_priority == generated_management_key_2.priority
        assert management_key_2_type == generated_management_key_2.key_type
        assert management_key_2_controller == generated_management_key_2.controller
        assert generated_management_key_2.public_key is not None
        assert generated_management_key_2.private_key is not None

        management_key_3_alias = "management-key-3"
        management_key_3_priority = 3
        management_key_3_type = KeyType.RSA

        did.management_key(
            management_key_3_alias, management_key_3_priority, management_key_3_type
        )
        generated_management_key_3 = did.management_keys[2]

        assert management_key_3_alias == generated_management_key_3.alias
        assert management_key_3_priority == generated_management_key_3.priority
        assert management_key_3_type == generated_management_key_3.key_type
        assert did.id == generated_management_key_3.controller
        assert generated_management_key_3.public_key is not None
        assert generated_management_key_3.private_key is not None
        assert 3 == len(did.management_keys)

    def test_invalid_alias_throws_exception(self, did):
        test_cases = ["myManagementKey", "my-m@nagement-key", "my_management_key"]
        for alias in test_cases:
            with pytest.raises(ValueError):
                did.management_key(alias, 1)

    def test_invalid_priority_throws_exception(self, did):
        test_cases = [-1, -2]
        for priority in test_cases:
            management_key_alias = "management-key-{}".format(str(priority))
            with pytest.raises(ValueError):
                did.management_key(management_key_alias, priority)

    def test_used_alias_throws_exception(self, did):
        management_key_alias = "management-key-1"
        did.management_key(management_key_alias, 1)
        with pytest.raises(ValueError):
            did.management_key(management_key_alias, 1)

    def test_invalid_key_type_throws_exception(self, did):
        management_key_alias = "management-key"
        management_key_type = "invalid_key_type"
        with pytest.raises(ValueError):
            did.management_key(management_key_alias, 1, management_key_type)

    def test_invalid_controller_throws_exception(self, did):
        test_cases = [
            (
                "management-key-1",
                "{}:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654h05f838b8005".format(
                    DID_METHOD_NAME
                ),
            ),
            (
                "management-key-2",
                "did:fctr:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b8005",
            ),
            (
                "management-key-3",
                "{}:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b800".format(
                    DID_METHOD_NAME
                ),
            ),
        ]

        for alias, controller in test_cases:
            with pytest.raises(ValueError):
                did.management_key(alias, 1, KeyType.EdDSA, controller)

    def test__repr__method(self, did):
        management_key_alias = "management-key-1"
        management_key_priority = 0

        did.management_key(management_key_alias, management_key_priority)
        generated_management_key = did.management_keys[0]

        expected__repr__method_output = (
            "<{}.{}(alias={}, priority={}, key_type={},"
            " controller={}, priority_requirement={})>".format(
                ManagementKey.__module__,
                ManagementKey.__name__,
                management_key_alias,
                management_key_priority,
                generated_management_key.underlying,
                generated_management_key.controller,
                None,
            )
        )

        assert str(generated_management_key) == expected__repr__method_output

    def test__repr__method_with_rsa_key(self, did):
        management_key_alias = "management-key-1"
        management_key_priority = 0
        management_key_type = KeyType.RSA

        did.management_key(
            management_key_alias, management_key_priority, management_key_type
        )
        generated_management_key = did.management_keys[0]

        expected__repr__method_output = (
            "<{}.{}(alias={}, priority={}, key_type={},"
            " controller={}, priority_requirement={})>".format(
                ManagementKey.__module__,
                ManagementKey.__name__,
                management_key_alias,
                management_key_priority,
                generated_management_key.underlying,
                generated_management_key.controller,
                None,
            )
        )

        assert str(generated_management_key) == expected__repr__method_output


class TestDidKeys:
    def test_add_did_keys(self, did):
        did_key_1_alias = "did-key-1"
        did_key_1_purpose = [DIDKeyPurpose.PublicKey]
        did.did_key(did_key_1_alias, did_key_1_purpose)
        generated_did_key_1 = did.did_keys[0]

        assert did_key_1_alias == generated_did_key_1.alias
        assert did_key_1_purpose == generated_did_key_1.purpose
        assert KeyType.EdDSA == generated_did_key_1.key_type
        assert did.id == generated_did_key_1.controller
        assert generated_did_key_1.priority_requirement is None

        did_key_2_alias = "did-key-2"
        did_key_2_purpose = [DIDKeyPurpose.PublicKey, DIDKeyPurpose.AuthenticationKey]
        did_key_2_type = KeyType.ECDSA
        did_key_2_controller = "{}:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b8005".format(
            DID_METHOD_NAME
        )
        did_key_2_priority_requirement = 1
        did.did_key(
            did_key_2_alias,
            did_key_2_purpose,
            did_key_2_type,
            did_key_2_controller,
            did_key_2_priority_requirement,
        )
        generated_did_key_2 = did.did_keys[1]

        assert did_key_2_alias == generated_did_key_2.alias
        assert did_key_2_purpose == generated_did_key_2.purpose
        assert did_key_2_type == generated_did_key_2.key_type
        assert did_key_2_controller == generated_did_key_2.controller
        assert (
            did_key_2_priority_requirement == generated_did_key_2.priority_requirement
        )
        assert 2 == len(did.did_keys)

    def test_invalid_alias_throws_exception(self, did):
        test_cases = ["myDidKey", "my-d!d-key", "my_did_key"]
        for alias in test_cases:
            with pytest.raises(ValueError):
                did.did_key(alias, [DIDKeyPurpose.PublicKey])

    def test_invalid_purpose_type_throws_exception(self, did):
        did_key_alias = "did-key"
        did_key_purpose = [DIDKeyPurpose.PublicKey, "InvalidPurposeType"]
        with pytest.raises(ValueError):
            did.did_key(did_key_alias, did_key_purpose)

    def test_used_alias_throws_exception(self, did):
        alias = "my-key-1"
        did.management_key(alias, 1)
        with pytest.raises(ValueError):
            did.did_key(alias, [DIDKeyPurpose.PublicKey])

    def test_invalid_key_type_throws_exception(self, did):
        did_key_alias = "management-key"
        did_key_type = "invalid_key_type"
        with pytest.raises(ValueError):
            did.did_key(did_key_alias, [DIDKeyPurpose.PublicKey], did_key_type)

    def test_invalid_controller_throws_exception(self, did):
        test_cases = [
            (
                "did-key-1",
                "did:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b8005",
            ),
            (
                "did-key-2",
                "did:fctr:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b800",
            ),
        ]

        for alias, controller in test_cases:
            with pytest.raises(ValueError):
                did.did_key(alias, [DIDKeyPurpose.PublicKey], KeyType.EdDSA, controller)

    def test_invalid_priority_requirement_throws_exception(self, did):
        test_cases = [-1, -2]
        for priority_requirement in test_cases:
            did_key_alias = "did-key-{}".format(str(priority_requirement))
            with pytest.raises(ValueError):
                did.did_key(
                    did_key_alias,
                    [DIDKeyPurpose.PublicKey],
                    KeyType.EdDSA,
                    None,
                    priority_requirement,
                )

    def test__repr__method(self, did):
        did_key_alias = "did-key-1"
        did_key_purpose = [DIDKeyPurpose.PublicKey]
        did_key_type = KeyType.EdDSA
        did_key_controller = "{}:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b8005".format(
            DID_METHOD_NAME
        )
        did_key_priority_requirement = 1

        did.did_key(
            did_key_alias,
            did_key_purpose,
            did_key_type,
            did_key_controller,
            did_key_priority_requirement,
        )
        generated_did_key = did.did_keys[0]

        expected__repr__method_output = (
            "<{}.{}(alias={}, purpose={}, key_type={},"
            " controller={}, priority_requirement={})>".format(
                DIDKey.__module__,
                DIDKey.__name__,
                did_key_alias,
                did_key_purpose,
                generated_did_key.underlying,
                did_key_controller,
                did_key_priority_requirement,
            )
        )

        assert str(generated_did_key) == expected__repr__method_output

    def test__repr__method_with_rsa_key(self, did):
        did_key_alias = "did-key-1"
        did_key_purpose = [DIDKeyPurpose.PublicKey, DIDKeyPurpose.AuthenticationKey]
        did_key_type = KeyType.RSA

        did.did_key(did_key_alias, did_key_purpose, did_key_type)
        generated_did_key = did.did_keys[0]

        expected__repr__method_output = (
            "<{}.{}(alias={}, purpose={}, key_type={},"
            " controller={}, priority_requirement={})>".format(
                DIDKey.__module__,
                DIDKey.__name__,
                did_key_alias,
                did_key_purpose,
                generated_did_key.underlying,
                generated_did_key.controller,
                None,
            )
        )

        assert str(generated_did_key) == expected__repr__method_output


class TestService:
    def test_add_service(self, did):
        service_1_alias = "photo-service"
        service_1_type = "PhotoStreamService"
        service_1_endpoint = "https://myphoto.com"
        did.service(service_1_alias, service_1_type, service_1_endpoint)
        generated_service_1 = did.services[0]

        assert service_1_alias == generated_service_1.alias
        assert service_1_type == generated_service_1.service_type
        assert service_1_endpoint == generated_service_1.endpoint
        assert generated_service_1.priority_requirement is None

        service_2_alias = "auth-service"
        service_2_type = "AuthenticationService"
        service_2_endpoint = "https://authenticateme.com"
        service_2_priority_requirement = 2
        did.service(
            service_2_alias,
            service_2_type,
            service_2_endpoint,
            service_2_priority_requirement,
        )
        generated_service_2 = did.services[1]

        assert service_2_alias == generated_service_2.alias
        assert service_2_type == generated_service_2.service_type
        assert service_2_endpoint == generated_service_2.endpoint
        assert (
            service_2_priority_requirement == generated_service_2.priority_requirement
        )
        assert 2 == len(did.services)

    def test_invalid_alias_throws_exception(self, did):
        service_type = "PhotoStreamService"
        service_endpoint = "https://myphoto.com"
        test_cases = ["myPhotoService", "my-ph@to-service", "my_photo_service"]
        for alias in test_cases:
            with pytest.raises(ValueError):
                did.service(alias, service_type, service_endpoint)

    def test_used_alias_throws_exception(self, did):
        service_alias = "my-photo-service"
        service_type = "PhotoStreamService"
        service_endpoint = "https://myphoto.com"
        did.service(service_alias, service_type, service_endpoint)
        with pytest.raises(ValueError):
            did.service(service_alias, service_type, service_endpoint)

    def test_empty_service_type_throws_exception(self, did):
        service_alias = "my-photo-service"
        service_type = ""
        service_endpoint = "https://myphoto.com"
        with pytest.raises(ValueError):
            did.service(service_alias, service_type, service_endpoint)

    def test_invalid_endpoint_throws_exception(self, did):
        service_type = "PhotoStreamService"
        test_cases = [
            ("service-1", "myservice.com"),
            ("service-2", "https//myphoto.com"),
        ]

        for alias, endpoint in test_cases:
            with pytest.raises(ValueError):
                did.service(alias, service_type, endpoint)

    def test_invalid_priority_requirement_throws_exception(self, did):
        service_type = "PhotoStreamService"
        service_endpoint = "https://myphoto.com"
        test_cases = [-1, -2]
        for priority_requirement in test_cases:
            service_alias = "service-{}".format(str(priority_requirement))
            with pytest.raises(ValueError):
                did.service(
                    service_alias, service_type, service_endpoint, priority_requirement
                )

    def test__repr__method(self, did):
        service_alias = "photo-service"
        service_type = "PhotoStreamService"
        service_endpoint = "https://myphoto.com"
        service_priority_requirement = 1
        did.service(
            service_alias, service_type, service_endpoint, service_priority_requirement
        )
        generated_service = did.services[0]

        expected__repr__method_output = (
            "<{}.{}(alias={}, service_type={}, "
            "endpoint={}, priority_requirement={})>".format(
                Service.__module__,
                Service.__name__,
                service_alias,
                service_type,
                service_endpoint,
                service_priority_requirement,
            )
        )

        assert str(generated_service) == expected__repr__method_output


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
        did.management_key("my-management-key-1", 0)
        did.management_key("my-management-key-2", 2)
        did.did_key(
            did_key_alias,
            did_key_purpose,
            did_key_type,
            did_key_controller,
            did_key_priority_requirement,
        )
        did.service(
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
