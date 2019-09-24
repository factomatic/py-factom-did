import hashlib
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
    )


@pytest.fixture
def man_key_2(did):
    return ManagementKey(
        alias="man-key-2", priority=0, controller=did, key_type=KeyType.EdDSA.value
    )


@pytest.fixture
def did_key_1(did):
    return DIDKey(
        alias="did-key-1",
        controller=did,
        key_type=KeyType.ECDSA.value,
        purpose=DIDKeyPurpose.AuthenticationKey.value,
    )


@pytest.fixture
def service_1(did):
    return Service(
        alias="service-1", service_type="some-service", endpoint="https://myservice.com"
    )


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

    def test_unknown_did_method_version(self, did, man_key_1):
        entry = {
            "extids": [b"DIDManagement", b"1.0.0"],
            "content": json.dumps(
                {
                    "didMethodVersion": "0.2.1",
                    "managementKey": [man_key_1.to_entry_dict(did)],
                }
            ).encode("utf-8"),
        }
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry])
        assert str(excinfo.value) == "Unknown DID method spec version: 0.2.1"

    def test_duplicate_management_keys(self, did, man_key_1):
        entry = {
            "extids": [b"DIDManagement", b"1.0.0"],
            "content": json.dumps(
                {
                    "didMethodVersion": "0.2.0",
                    "managementKey": [
                        man_key_1.to_entry_dict(did),
                        man_key_1.to_entry_dict(did),
                    ],
                }
            ).encode("utf-8"),
        }
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry])
        assert (
            str(excinfo.value)
            == "Malformed DIDManagement entry: Duplicate management key found"
        )

    def test_duplicate_did_keys(self, did, man_key_1, did_key_1):
        entry = {
            "extids": [b"DIDManagement", b"1.0.0"],
            "content": json.dumps(
                {
                    "didMethodVersion": "0.2.0",
                    "managementKey": [man_key_1.to_entry_dict(did)],
                    "didKey": [
                        did_key_1.to_entry_dict(did),
                        did_key_1.to_entry_dict(did),
                    ],
                }
            ).encode("utf-8"),
        }
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry])
        assert (
            str(excinfo.value)
            == "Malformed DIDManagement entry: Duplicate DID key found"
        )

    def test_duplicate_services(self, did, man_key_1, service_1):
        entry = {
            "extids": [b"DIDManagement", b"1.0.0"],
            "content": json.dumps(
                {
                    "didMethodVersion": "0.2.0",
                    "managementKey": [man_key_1.to_entry_dict(did)],
                    "service": [
                        service_1.to_entry_dict(did),
                        service_1.to_entry_dict(did),
                    ],
                }
            ).encode("utf-8"),
        }
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry])
        assert (
            str(excinfo.value)
            == "Malformed DIDManagement entry: Duplicate service found"
        )


def test_valid_did_management_entry(did, man_key_1, did_key_1, service_1):
    entry = {
        "extids": [b"DIDManagement", b"1.0.0"],
        "content": json.dumps(
            {
                "didMethodVersion": "0.2.0",
                "managementKey": [man_key_1.to_entry_dict(did)],
                "didKey": [did_key_1.to_entry_dict(did)],
                "service": [service_1.to_entry_dict(did)],
            }
        ).encode("utf-8"),
    }

    management_keys, did_keys, services, processed_entries = parse_did_chain_entries(
        [entry]
    )

    man_key_1.private_key = None
    did_key_1.private_key = None

    assert management_keys == {"man-key-1": man_key_1}
    assert did_keys == {"did-key-1": did_key_1}
    assert services == {"service-1": service_1}
    assert processed_entries == 1


def test_did_deactivation(did, man_key_1, did_key_1, service_1):
    man_key_1_dict = man_key_1.to_entry_dict(did)
    entry_1 = {
        "extids": [b"DIDManagement", b"1.0.0"],
        "content": json.dumps(
            {
                "didMethodVersion": "0.2.0",
                "managementKey": [man_key_1_dict],
                "didKey": [did_key_1.to_entry_dict(did)],
                "service": [service_1.to_entry_dict(did)],
            }
        ).encode("utf-8"),
    }

    content = ""
    ext_ids = ["DIDDeactivation", "1.0.0", man_key_1_dict["id"]]
    data_to_sign = "".join([*ext_ids, content]).replace(" ", "").encode("utf-8")
    signature = man_key_1.sign(hashlib.sha256(data_to_sign).digest())
    entry_2 = {
        "extids": [
            b"DIDDeactivation",
            b"1.0.0",
            man_key_1_dict["id"].encode("utf-8"),
            signature,
        ],
        "content": b"",
    }

    # Should be ignored
    ext_ids = ["DIDUpdate", "1.0.0", man_key_1_dict["id"]]
    content = {"revoke": {"service": [{"id": service_1.alias}]}}
    data_to_sign = (
        "".join([*ext_ids, json.dumps(content)]).replace(" ", "").encode("utf-8")
    )
    signature = man_key_1.sign(hashlib.sha256(data_to_sign).digest())
    entry_3 = {
        "extids": [
            b"DIDUpdate",
            b"1.0.0",
            man_key_1_dict["id"].encode("utf-8"),
            signature,
        ]
    }

    management_keys, did_keys, services, processed_entries = parse_did_chain_entries(
        [entry_1, entry_2, entry_3]
    )
    assert management_keys == {}
    assert did_keys == {}
    assert services == {}
    assert processed_entries == 2
