import json
import secrets

import pytest

from client.constants import DID_METHOD_NAME
from client.enums import DIDKeyPurpose, KeyType
from client.keys import ManagementKey, DIDKey
from client.service import Service
from resolver.exceptions import InvalidDIDChain
from resolver.parser import parse_did_chain_entries


@pytest.fixture
def did():
    return "{}:{}".format(DID_METHOD_NAME, secrets.token_hex(32))


@pytest.fixture
def man_key_1(did):
    return ManagementKey(
        alias="man-key-1", priority=0, controller=did, key_type=KeyType.ECDSA.value
    ).to_entry_dict(did)


@pytest.fixture
def man_key_2(did):
    return ManagementKey(
        alias="man-key-2", priority=0, controller=did, key_type=KeyType.EdDSA.value
    ).to_entry_dict(did)


@pytest.fixture
def did_key_1(did):
    return DIDKey(
        alias="did-key-1",
        controller=did,
        key_type=KeyType.ECDSA.value,
        purpose=DIDKeyPurpose.AuthenticationKey.value,
    ).to_entry_dict(did)


@pytest.fixture
def service_1(did):
    return Service(
        alias="my-service",
        service_type="some-service",
        endpoint="https://myservice.com",
    ).to_entry_dict(did)


class TestInvalidDIDManagementEntry:
    def test_invalid_json(self):
        entry = {
            "extids": [b"DIDManagement", b"1.0.0", b"asdfasdfasdf"],
            "content": b"asdf",
        }

        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry])
        assert str(excinfo.value) == "DIDManagement entry content must be valid JSON"

    def test_invalid_unicode(self):
        entry = {
            "extids": [b"DIDManagement", b"1.0.0", b"asdfasdfasdf"],
            "content": b"\xdc\x9d`\x90",
        }

        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry])
        assert str(excinfo.value) == "DIDManagement entry content must be valid JSON"

    def test_insufficient_ext_ids(self):
        entry = {
            "extids": [b"DIDManagement"],
            "content": json.dumps({"a": 1}).encode("utf-8"),
        }

        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry])
        assert str(excinfo.value) == "DIDManagement entry has insufficient ExtIDs"

    def test_unknown_entry_type(self):
        entry = {
            "extids": [b"DIDManagements", b"1.0.0"],
            "content": json.dumps({"a": 1}).encode("utf-8"),
        }

        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry])
        assert str(excinfo.value) == "Unknown schema version or entry type"

    def test_unknown_schema_version(self):
        entry = {
            "extids": [b"DIDManagement", b"1.0.1"],
            "content": json.dumps({"a": 1}).encode("utf-8"),
        }

        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry])
        assert str(excinfo.value) == "Unknown schema version or entry type"

    def test_invalid_schema(self):
        entry = {
            "extids": [b"DIDManagement", b"1.0.0"],
            "content": json.dumps({"didMethodVersion": "0.2.0"}).encode("utf-8"),
        }
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry])
        assert str(excinfo.value) == "Invalid DIDManagement entry content"

    def test_unknown_did_method_version(self, man_key_1):
        entry = {
            "extids": [b"DIDManagement", b"1.0.0"],
            "content": json.dumps(
                {"didMethodVersion": "0.2.1", "managementKey": [man_key_1]}
            ).encode("utf-8"),
        }
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry])
        assert str(excinfo.value) == "Unknown DID method spec version: 0.2.1"

    def test_duplicate_management_keys(self, man_key_1):
        entry = {
            "extids": [b"DIDManagement", b"1.0.0"],
            "content": json.dumps(
                {"didMethodVersion": "0.2.0", "managementKey": [man_key_1, man_key_1]}
            ).encode("utf-8"),
        }
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry])
        assert (
            str(excinfo.value)
            == "Malformed DIDManagement entry: Duplicate management key found"
        )

    def test_duplicate_did_keys(self, man_key_1, did_key_1):
        entry = {
            "extids": [b"DIDManagement", b"1.0.0"],
            "content": json.dumps(
                {
                    "didMethodVersion": "0.2.0",
                    "managementKey": [man_key_1],
                    "didKey": [did_key_1, did_key_1],
                }
            ).encode("utf-8"),
        }
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry])
        assert (
            str(excinfo.value)
            == "Malformed DIDManagement entry: Duplicate DID key found"
        )

    def test_duplicate_services(self, man_key_1, service_1):
        print("service in test_duplicate_services: {}".format(service_1))
        entry = {
            "extids": [b"DIDManagement", b"1.0.0"],
            "content": json.dumps(
                {
                    "didMethodVersion": "0.2.0",
                    "managementKey": [man_key_1],
                    "service": [service_1, service_1],
                }
            ).encode("utf-8"),
        }
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry])
        assert (
            str(excinfo.value)
            == "Malformed DIDManagement entry: Duplicate service found"
        )


def test_valid_did_management_entry(man_key_1, did_key_1, service_1):
    entry = {
        "extids": [b"DIDManagement", b"1.0.0"],
        "content": json.dumps(
            {
                "didMethodVersion": "0.2.0",
                "managementKey": [man_key_1],
                "didKey": [did_key_1],
                "service": [service_1],
            }
        ).encode("utf-8"),
    }

    parse_did_chain_entries([entry])
