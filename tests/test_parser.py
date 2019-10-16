from functools import reduce
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
def man_key_3(did):
    return ManagementKey(
        alias="man-key-3", priority=1, controller=did, key_type=KeyType.EdDSA.value
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


@pytest.fixture
def service_2(did):
    return Service(
        alias="service-2",
        service_type="some-service-2",
        endpoint="https://myservice-2.com",
        priority_requirement=0,
    )


@pytest.fixture
def management_entry():
    def _management_entry(content, ext_ids=None):
        if ext_ids is None:
            ext_ids = ["DIDManagement", "1.0.0", secrets.token_bytes(32)]
        if type(content) is dict and "didMethodVersion" not in content:
            content["didMethodVersion"] = "0.2.0"
        ext_ids = [
            ext_id if type(ext_id) is bytes else ext_id.encode("utf-8")
            for ext_id in ext_ids
        ]
        content = (
            json.dumps(content).encode("utf-8")
            if type(content) is dict
            else content.encode("utf-8")
        )
        return {
            "extids": ext_ids,
            "content": content,
            "entryhash": hashlib.sha256(
                reduce(lambda x, y: x + y, ext_ids) + content
            ).digest(),
        }

    return _management_entry


@pytest.fixture
def update_entry():
    def _update_entry(did, signing_key, content, ext_ids=None):
        if ext_ids is None:
            ext_ids = ["DIDUpdate", "1.0.0", signing_key.full_id(did)]
        content = json.dumps(content) if type(content) is dict else content
        data_to_sign = "".join([*ext_ids, content]).replace(" ", "").encode("utf-8")
        signature = signing_key.sign(hashlib.sha256(data_to_sign).digest())
        return {
            "extids": [
                ext_ids[0].encode("utf-8"),
                ext_ids[1].encode("utf-8"),
                signing_key.full_id(did).encode("utf-8"),
                signature,
            ],
            "content": content.replace(" ", "").encode("utf-8"),
            "entryhash": hashlib.sha256(
                data_to_sign + signature + content.replace(" ", "").encode("utf-8")
            ).digest(),
        }

    return _update_entry


@pytest.fixture
def deactivation_entry():
    def _deactivation_entry(did, signing_key, content="", ext_ids=None):
        if ext_ids is None:
            ext_ids = ["DIDDeactivation", "1.0.0", signing_key.full_id(did)]
        data_to_sign = "".join([*ext_ids, content]).replace(" ", "").encode("utf-8")
        signature = signing_key.sign(hashlib.sha256(data_to_sign).digest())
        return {
            "extids": [
                ext_ids[0].encode("utf-8"),
                ext_ids[1].encode("utf-8"),
                signing_key.full_id(did).encode("utf-8"),
                signature,
            ],
            "content": b"",
            "entryhash": hashlib.sha256(data_to_sign + signature).digest(),
        }

    return _deactivation_entry


@pytest.fixture
def version_upgrade_entry():
    def _deactivation_entry(did, signing_key, version, ext_ids=None):
        if ext_ids is None:
            ext_ids = ["DIDMethodVersionUpgrade", "1.0.0", signing_key.full_id(did)]
        content = json.dumps({"didMethodVersion": version})
        data_to_sign = "".join([*ext_ids, content]).replace(" ", "").encode("utf-8")
        signature = signing_key.sign(hashlib.sha256(data_to_sign).digest())
        return {
            "extids": [
                ext_ids[0].encode("utf-8"),
                ext_ids[1].encode("utf-8"),
                signing_key.full_id(did).encode("utf-8"),
                signature,
            ],
            "content": content.replace(" ", "").encode("utf-8"),
            "entryhash": hashlib.sha256(data_to_sign + signature).digest(),
        }

    return _deactivation_entry


class TestInvalidDIDManagementEntry:
    def test_invalid_json(self, management_entry):
        entry = management_entry("asdf")
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry])
        assert str(excinfo.value) == "DIDManagement entry content must be valid JSON"

    def test_invalid_unicode(self, management_entry):
        entry = management_entry("\xdc\x9d`\x90")
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry])
        assert str(excinfo.value) == "DIDManagement entry content must be valid JSON"

    def test_insufficient_ext_ids(self, management_entry):
        entry = management_entry({"a": 1}, ["DIDManagement"])
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry])
        assert str(excinfo.value) == "DIDManagement entry has insufficient ExtIDs"

    def test_unknown_entry_type(self, management_entry):
        entry = management_entry({"a": 1}, ["DIDManagements", "1.0.0"])
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry])
        assert str(excinfo.value) == "First entry must be of type DIDManagement"

    def test_unknown_schema_version(self, management_entry):
        entry = management_entry({"a": 1}, ["DIDManagement", "1.0.1"])
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry])
        assert str(excinfo.value) == "Unknown schema version or entry type"

    def test_invalid_schema(self, management_entry):
        entry = management_entry({})
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry])
        assert str(excinfo.value) == "Invalid DIDManagement entry content"

    def test_unknown_did_method_version(self, did, man_key_1, management_entry):
        entry = management_entry(
            {
                "didMethodVersion": "0.3.0",
                "managementKey": [man_key_1.to_entry_dict(did)],
            }
        )
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry])
        assert str(excinfo.value) == "Invalid DIDManagement entry content"

    def test_duplicate_management_keys(self, did, man_key_1, management_entry):
        entry = management_entry(
            {
                "managementKey": [
                    man_key_1.to_entry_dict(did),
                    man_key_1.to_entry_dict(did),
                ]
            }
        )
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry])
        assert (
            str(excinfo.value)
            == "Malformed DIDManagement entry: Duplicate management key found"
        )

    def test_duplicate_did_keys(self, did, man_key_1, did_key_1, management_entry):
        entry = management_entry(
            {
                "managementKey": [man_key_1.to_entry_dict(did)],
                "didKey": [did_key_1.to_entry_dict(did), did_key_1.to_entry_dict(did)],
            }
        )
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry])
        assert (
            str(excinfo.value)
            == "Malformed DIDManagement entry: Duplicate DID key found"
        )

    def test_duplicate_services(self, did, man_key_1, service_1, management_entry):
        entry = management_entry(
            {
                "managementKey": [man_key_1.to_entry_dict(did)],
                "service": [service_1.to_entry_dict(did), service_1.to_entry_dict(did)],
            }
        )
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry])
        assert (
            str(excinfo.value)
            == "Malformed DIDManagement entry: Duplicate service found"
        )

    def test_no_management_key_with_priority_zero(
        self, did, man_key_3, management_entry
    ):
        entry = management_entry({"managementKey": [man_key_3.to_entry_dict(did)]})
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry])
        assert (
            str(excinfo.value)
            == "Malformed DIDManagement entry: Entry must contain at least one management key with priority 0"
        )


def test_valid_did_management_entry(
    did, man_key_1, did_key_1, service_1, management_entry
):
    entry = management_entry(
        {
            "managementKey": [man_key_1.to_entry_dict(did)],
            "didKey": [did_key_1.to_entry_dict(did)],
            "service": [service_1.to_entry_dict(did)],
        }
    )

    management_keys, did_keys, services = parse_did_chain_entries([entry])

    man_key_1.private_key = None
    did_key_1.private_key = None

    assert management_keys == {"man-key-1": man_key_1}
    assert did_keys == {"did-key-1": did_key_1}
    assert services == {"service-1": service_1}


class TestDIDDeactivation:
    def test_did_deactivation_with_signature_from_insufficient_priority(
        self, did, man_key_1, man_key_3, management_entry, deactivation_entry
    ):
        man_key_1_dict = man_key_1.to_entry_dict(did)
        man_key_3_dict = man_key_3.to_entry_dict(did)

        entry_1 = management_entry({"managementKey": [man_key_1_dict, man_key_3_dict]})
        entry_2 = deactivation_entry(did, man_key_3)

        management_keys, did_keys, services = parse_did_chain_entries(
            [entry_1, entry_2]
        )
        assert len(management_keys) == 2

    def test_valid_did_deactivation(
        self,
        did,
        man_key_1,
        did_key_1,
        service_1,
        deactivation_entry,
        management_entry,
        update_entry,
    ):
        man_key_1_dict = man_key_1.to_entry_dict(did)
        entry_1 = management_entry(
            {
                "managementKey": [man_key_1_dict],
                "didKey": [did_key_1.to_entry_dict(did)],
                "service": [service_1.to_entry_dict(did)],
            }
        )

        entry_2 = deactivation_entry(did, man_key_1)

        # Should be ignored
        content = {"revoke": {"service": [{"id": service_1.alias}]}}
        entry_3 = update_entry(did, man_key_1, content)

        management_keys, did_keys, services = parse_did_chain_entries(
            [entry_1, entry_2, entry_3]
        )
        assert management_keys == {}
        assert did_keys == {}
        assert services == {}


class TestUpdate:
    def test_update_as_first_entry(self, did, man_key_1, service_1, update_entry):
        content = {"add": {"service": [service_1.to_entry_dict(did)]}}
        entry = update_entry(did, man_key_1, content)
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry])

        assert str(excinfo.value) == "First entry must be of type DIDManagement"

    def test_update_with_invalid_signature(
        self, did, man_key_1, service_1, management_entry, update_entry
    ):
        entry_1 = management_entry(
            {
                "managementKey": [man_key_1.to_entry_dict(did)],
                "service": [service_1.to_entry_dict(did)],
            }
        )
        content = {"revoke": {"service": [{"id": service_1.alias}]}}
        entry_2 = update_entry(did, man_key_1, content)

        # Modify the signature to an invalid value
        entry_2["extids"][3] = secrets.token_bytes(64)
        _, _, services = parse_did_chain_entries([entry_1, entry_2])

        # Make sure the service hasn't been revoked
        assert len(services) == 1

    def test_update_with_signature_from_key_with_insufficient_priority(
        self, did, man_key_1, man_key_3, service_2, management_entry, update_entry
    ):
        entry_1 = management_entry(
            {
                "managementKey": [
                    man_key_1.to_entry_dict(did),
                    man_key_3.to_entry_dict(did),
                ],
                "service": [service_2.to_entry_dict(did)],
            }
        )
        content = {"revoke": {"service": [{"id": service_2.alias}]}}
        entry_2 = update_entry(did, man_key_3, content)

        _, _, services = parse_did_chain_entries([entry_1, entry_2])

        # Make sure the service hasn't been revoked
        assert len(services) == 1

    def test_update_with_signature_from_did_key(
        self, did, man_key_1, did_key_1, service_1, management_entry, update_entry
    ):
        entry_1 = management_entry(
            {
                "managementKey": [man_key_1.to_entry_dict(did)],
                "didKey": [did_key_1.to_entry_dict(did)],
            }
        )
        content = {
            "revoke": {"didKey": [{"id": did_key_1.alias}]},
            "add": {"service": [service_1.to_entry_dict(did)]},
        }
        entry_2 = update_entry(did, did_key_1, content)

        management_keys, did_keys, services = parse_did_chain_entries(
            [entry_1, entry_2]
        )
        assert len(management_keys) == 1
        assert len(did_keys) == 1
        assert len(services) == 0

    def test_update_with_signature_from_revoked_management_key(
        self,
        did,
        man_key_1,
        man_key_2,
        did_key_1,
        service_1,
        management_entry,
        update_entry,
    ):
        entry_1 = management_entry(
            {
                "managementKey": [
                    man_key_1.to_entry_dict(did),
                    man_key_2.to_entry_dict(did),
                ]
            }
        )
        content = {
            "revoke": {"managementKey": [{"id": man_key_2.alias}]},
            "add": {"service": [service_1.to_entry_dict(did)]},
        }
        entry_2 = update_entry(did, man_key_2, content)
        content = {"add": {"didKey": [did_key_1.to_entry_dict(did)]}}
        entry_3 = update_entry(did, man_key_2, content)

        management_keys, did_keys, services = parse_did_chain_entries(
            [entry_1, entry_2, entry_3]
        )
        assert len(management_keys) == 1
        assert len(services) == 1
        assert len(did_keys) == 0

        assert man_key_2.alias not in management_keys

    def test_revocation_of_nonexistent_key(
        self,
        did,
        man_key_1,
        man_key_2,
        did_key_1,
        service_1,
        management_entry,
        update_entry,
    ):
        entry_1 = management_entry(
            {
                "managementKey": [man_key_1.to_entry_dict(did)],
                "didKey": [did_key_1.to_entry_dict(did)],
                "service": [service_1.to_entry_dict(did)],
            }
        )
        content = {
            "revoke": {
                "managementKey": [{"id": man_key_2.alias}],
                "service": [{"id": service_1.alias}],
            }
        }
        entry_2 = update_entry(did, man_key_1, content)

        management_keys, did_keys, services = parse_did_chain_entries(
            [entry_1, entry_2]
        )

        assert len(management_keys) == 1
        assert len(did_keys) == 1
        assert len(services) == 1

        assert man_key_1.alias in management_keys
        assert service_1.alias in services
        assert did_key_1.alias in did_keys

    def test_update_after_unsuccessful_version_upgrade(
        self,
        did,
        man_key_1,
        man_key_2,
        management_entry,
        update_entry,
        version_upgrade_entry,
    ):
        entry_1 = management_entry(
            {
                "managementKey": [
                    man_key_1.to_entry_dict(did),
                    man_key_2.to_entry_dict(did),
                ]
            }
        )
        entry_2 = version_upgrade_entry(did, man_key_1, "0.1.0")
        content = {"revoke": {"managementKey": [{"id": man_key_1.alias}]}}
        entry_3 = update_entry(did, man_key_1, content)

        management_keys, _, _ = parse_did_chain_entries([entry_1, entry_2, entry_3])

        assert len(management_keys) == 1
        assert man_key_1.alias not in management_keys

    def test_update_after_successful_version_upgrade(
        self,
        did,
        man_key_1,
        man_key_2,
        management_entry,
        update_entry,
        version_upgrade_entry,
    ):
        entry_1 = management_entry(
            {
                "managementKey": [
                    man_key_1.to_entry_dict(did),
                    man_key_2.to_entry_dict(did),
                ]
            }
        )
        entry_2 = version_upgrade_entry(did, man_key_1, "0.3.0")
        content = {"revoke": {"managementKey": [{"id": man_key_1.alias}]}}
        entry_3 = update_entry(did, man_key_1, content)

        management_keys, _, _ = parse_did_chain_entries([entry_1, entry_2, entry_3])

        assert len(management_keys) == 2

    def test_replay_attack(self):
        pass

    def test_multiple_valid_and_invalid_updates(self):
        pass
