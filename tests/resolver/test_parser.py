from functools import reduce
import hashlib
import json
import secrets

import pytest

from factom_did.client.constants import DID_METHOD_NAME
from factom_did.client.enums import DIDKeyPurpose, KeyType, Network
from factom_did.client.keys.did import DIDKey
from factom_did.client.keys.ecdsa import ECDSASecp256k1Key
from factom_did.client.keys.management import ManagementKey
from factom_did.client.service import Service
from factom_did.resolver.exceptions import InvalidDIDChain
from factom_did.resolver.parser import parse_did_chain_entries


@pytest.fixture
def did():
    return "{}:{}".format(DID_METHOD_NAME, secrets.token_hex(32))


@pytest.fixture
def did_mainnet(did):
    return "{}:mainnet:{}".format(DID_METHOD_NAME, did.split(":")[-1])


@pytest.fixture
def did_testnet(did):
    return "{}:testnet:{}".format(DID_METHOD_NAME, did.split(":")[-1])


@pytest.fixture
def did_2():
    return "{}:{}".format(DID_METHOD_NAME, secrets.token_hex(32))


@pytest.fixture
def chain_id(did):
    return did.split(":")[-1]


@pytest.fixture
def chain_id_2(did_2):
    return did_2.split(":")[-1]


@pytest.fixture
def full_did():
    return "{}:{}:{}".format(
        DID_METHOD_NAME, Network.Mainnet.value, secrets.token_hex(32)
    )


@pytest.fixture
def chain_id_3(full_did):
    return full_did.split(":")[-1]


@pytest.fixture
def man_key_1(did):
    return ManagementKey(
        alias="man-key-1", priority=0, controller=did, key_type=KeyType.ECDSA
    )


@pytest.fixture
def man_key_1_public_only(did):
    key = ECDSASecp256k1Key()
    return ManagementKey(
        alias="man-key-1",
        priority=0,
        controller=did,
        key_type=KeyType.ECDSA,
        public_key=key.public_key,
    )


@pytest.fixture
def man_key_2(did):
    return ManagementKey(
        alias="man-key-2", priority=0, controller=did, key_type=KeyType.EdDSA
    )


@pytest.fixture
def man_key_3(did):
    return ManagementKey(
        alias="man-key-3",
        priority=1,
        controller=did,
        key_type=KeyType.EdDSA,
        priority_requirement=1,
    )


@pytest.fixture
def man_key_4(did):
    return ManagementKey(
        alias="man-key-4",
        priority=2,
        controller=did,
        key_type=KeyType.EdDSA,
        priority_requirement=1,
    )


@pytest.fixture
def man_key_5(did_2):
    return ManagementKey(
        alias="man-key-5", priority=0, controller=did_2, key_type=KeyType.ECDSA
    )


@pytest.fixture
def man_key_6(did):
    return ManagementKey(
        alias="man-key-6",
        priority=1,
        controller=did,
        key_type=KeyType.EdDSA,
        priority_requirement=1,
    )


@pytest.fixture
def did_key_1(did):
    return DIDKey(
        alias="did-key-1",
        controller=did,
        key_type=KeyType.ECDSA,
        purpose=DIDKeyPurpose.AuthenticationKey,
    )


@pytest.fixture
def did_key_1_public_only(did):
    key = ECDSASecp256k1Key()
    return DIDKey(
        alias="did-key-1",
        controller=did,
        key_type=KeyType.ECDSA,
        purpose=DIDKeyPurpose.AuthenticationKey,
        public_key=key.public_key,
    )


@pytest.fixture
def did_key_2(did):
    return DIDKey(
        alias="did-key-2",
        controller=did,
        key_type=KeyType.EdDSA,
        purpose=[DIDKeyPurpose.PublicKey, DIDKeyPurpose.AuthenticationKey],
        priority_requirement=2,
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


class TestDIDManagementEntry:
    def test_invalid_json(self, management_entry, chain_id):
        entry = management_entry("asdf")
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry], chain_id)
        assert str(excinfo.value) == "DIDManagement entry content must be valid JSON"

    def test_invalid_unicode(self, management_entry, chain_id):
        entry = management_entry("\xdc\x9d`\x90")
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry], chain_id)
        assert str(excinfo.value) == "DIDManagement entry content must be valid JSON"

    def test_insufficient_ext_ids(self, management_entry, chain_id):
        entry = management_entry({"a": 1}, ["DIDManagement"])
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry], chain_id)
        assert str(excinfo.value) == "DIDManagement entry has insufficient ExtIDs"

    def test_unknown_entry_type(self, management_entry, chain_id):
        entry = management_entry({"a": 1}, ["DIDManagements", "1.0.0"])
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry], chain_id)
        assert str(excinfo.value) == "First entry must be of type DIDManagement"

    def test_unknown_schema_version(self, management_entry, chain_id):
        entry = management_entry({"a": 1}, ["DIDManagement", "1.0.1"])
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry], chain_id)
        assert str(excinfo.value) == "Unknown schema version or entry type"

    def test_invalid_schema(self, management_entry, chain_id):
        entry = management_entry({})
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry], chain_id)
        assert str(excinfo.value) == "Invalid DIDManagement entry content"

    def test_unknown_did_method_version(
        self, did, man_key_1, management_entry, chain_id
    ):
        entry = management_entry(
            {
                "didMethodVersion": "0.3.0",
                "managementKey": [man_key_1.to_entry_dict(did)],
            }
        )
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry], chain_id)
        assert str(excinfo.value) == "Invalid DIDManagement entry content"

    def test_duplicate_management_keys(
        self, full_did, man_key_1, management_entry, chain_id_3
    ):
        entry = management_entry(
            {
                "managementKey": [
                    man_key_1.to_entry_dict(full_did),
                    man_key_1.to_entry_dict(full_did),
                ]
            }
        )
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry], chain_id_3)
        assert (
            str(excinfo.value)
            == "Malformed DIDManagement entry: Duplicate management key found"
        )

    def test_duplicate_did_keys(
        self, did, man_key_1, did_key_1, management_entry, chain_id
    ):
        entry = management_entry(
            {
                "managementKey": [man_key_1.to_entry_dict(did)],
                "didKey": [did_key_1.to_entry_dict(did), did_key_1.to_entry_dict(did)],
            }
        )
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry], chain_id)
        assert (
            str(excinfo.value)
            == "Malformed DIDManagement entry: Duplicate DID key found"
        )

    def test_duplicate_services(
        self, did, man_key_1, service_1, management_entry, chain_id
    ):
        entry = management_entry(
            {
                "managementKey": [man_key_1.to_entry_dict(did)],
                "service": [service_1.to_entry_dict(did), service_1.to_entry_dict(did)],
            }
        )
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry], chain_id)
        assert (
            str(excinfo.value)
            == "Malformed DIDManagement entry: Duplicate service found"
        )

    def test_no_management_key_with_priority_zero(
        self, did, man_key_3, management_entry, chain_id
    ):
        entry = management_entry({"managementKey": [man_key_3.to_entry_dict(did)]})
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry], chain_id)
        assert (
            str(excinfo.value)
            == "Malformed DIDManagement entry: Entry must contain at least one management key with priority 0"
        )

    def test_duplicate_management_entries(
        self, did, man_key_1, management_entry, chain_id
    ):
        entry_1 = management_entry({"managementKey": [man_key_1.to_entry_dict(did)]})
        entry_2 = management_entry({"managementKey": [man_key_1.to_entry_dict(did)]})
        entry_2["extids"].append("asdf")
        management_keys, _, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )

        assert skipped_entries == 1
        assert len(management_keys) == 1
        assert man_key_1.alias in management_keys

    def test_management_keys_with_key_ids_for_different_chain(
        self, did, did_2, man_key_1, man_key_5, management_entry, chain_id
    ):
        entry = management_entry(
            {
                "managementKey": [
                    man_key_1.to_entry_dict(did),
                    man_key_5.to_entry_dict(did_2),
                ]
            }
        )

        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry], chain_id)

        assert str(excinfo.value).startswith(
            "Malformed DIDManagement entry: Invalid key identifier"
        )

    def test_with_malformed_key_identifier(
        self, did, man_key_1, management_entry, chain_id
    ):
        entry_1 = management_entry(
            {
                "managementKey": [
                    {
                        "id": "did:fatcom:{}#man-key-1".format(
                            chain_id
                        ),  # malformed (fatcom should be factom)
                        "type": "ECDSASecp256k1VerificationKey",
                        "priority": 0,
                        "controller": did,
                        "publicKeyBase58": man_key_1.underlying.get_public_key_on_chain_repr()[
                            1
                        ],
                    }
                ]
            }
        )
        with pytest.raises(InvalidDIDChain):
            parse_did_chain_entries([entry_1], chain_id)

    def test_with_partial_key_identifier(
        self, did, man_key_1, management_entry, chain_id
    ):
        entry_1 = management_entry(
            {
                "managementKey": [
                    {
                        "id": "man-key-1",
                        "type": "ECDSASecp256k1VerificationKey",
                        "priority": 0,
                        "controller": did,
                        "publicKeyBase58": man_key_1.underlying.get_public_key_on_chain_repr()[
                            1
                        ],
                    }
                ]
            }
        )

        management_keys, _, _, skipped_entries = parse_did_chain_entries(
            [entry_1], chain_id
        )

        assert len(management_keys) == 1
        assert skipped_entries == 0

    def test_with_mainnet_management_key_on_testnet(
        self, did_mainnet, man_key_1, management_entry, chain_id
    ):
        entry = management_entry(
            {"managementKey": [man_key_1.to_entry_dict(did_mainnet)]}
        )

        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry], chain_id, Network.Testnet)
        assert str(excinfo.value).find("for network ID 'testnet'") != -1

    def test_with_mainnet_did_key_on_testnet(
        self, did_mainnet, did_testnet, man_key_1, did_key_1, management_entry, chain_id
    ):
        entry = management_entry(
            {
                "managementKey": [man_key_1.to_entry_dict(did_testnet)],
                "didKey": [did_key_1.to_entry_dict(did_mainnet)],
            }
        )

        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry], chain_id, Network.Testnet)
        assert str(excinfo.value).find("for network ID 'testnet'") != -1

    def test_with_mainnet_service_on_testnet(
        self, did_mainnet, did_testnet, man_key_1, service_1, management_entry, chain_id
    ):
        entry = management_entry(
            {
                "managementKey": [man_key_1.to_entry_dict(did_testnet)],
                "service": [service_1.to_entry_dict(did_mainnet)],
            }
        )

        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry], chain_id, Network.Testnet)
        assert str(excinfo.value).find("for network ID 'testnet'") != -1

    def test_valid_did_management_entry(
        self,
        did,
        man_key_1_public_only,
        did_key_1_public_only,
        service_1,
        management_entry,
        chain_id,
    ):
        entry = management_entry(
            {
                "managementKey": [man_key_1_public_only.to_entry_dict(did)],
                "didKey": [did_key_1_public_only.to_entry_dict(did)],
                "service": [service_1.to_entry_dict(did)],
            }
        )

        management_keys, did_keys, services, skipped_entries = parse_did_chain_entries(
            [entry], chain_id
        )

        assert management_keys == {"man-key-1": man_key_1_public_only}
        assert did_keys == {"did-key-1": did_key_1_public_only}
        assert services == {"service-1": service_1}
        assert skipped_entries == 0


class TestDIDDeactivationEntry:
    def test_with_unknown_method_spec_version(
        self,
        did,
        man_key_1,
        management_entry,
        version_upgrade_entry,
        deactivation_entry,
        chain_id,
    ):
        entry_1 = management_entry({"managementKey": [man_key_1.to_entry_dict(did)]})
        entry_2 = version_upgrade_entry(did, man_key_1, "0.4.0")
        entry_3 = deactivation_entry(did, man_key_1)

        management_keys, _, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2, entry_3], chain_id
        )

        assert len(management_keys) == 1
        assert skipped_entries == 1

    def test_with_signature_from_insufficient_priority(
        self, did, man_key_1, man_key_3, management_entry, deactivation_entry, chain_id
    ):
        man_key_1_dict = man_key_1.to_entry_dict(did)
        man_key_3_dict = man_key_3.to_entry_dict(did)

        entry_1 = management_entry({"managementKey": [man_key_1_dict, man_key_3_dict]})
        entry_2 = deactivation_entry(did, man_key_3)

        management_keys, did_keys, services, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )
        assert len(management_keys) == 2
        assert skipped_entries == 1

    def test_valid_deactivation(
        self,
        full_did,
        man_key_1,
        did_key_1,
        service_1,
        deactivation_entry,
        management_entry,
        update_entry,
        chain_id_3,
    ):
        man_key_1_dict = man_key_1.to_entry_dict(full_did)
        entry_1 = management_entry(
            {
                "managementKey": [man_key_1_dict],
                "didKey": [did_key_1.to_entry_dict(full_did)],
                "service": [service_1.to_entry_dict(full_did)],
            }
        )

        entry_2 = deactivation_entry(full_did, man_key_1)

        # Should be ignored
        content = {"revoke": {"service": [{"id": service_1.alias}]}}
        entry_3 = update_entry(full_did, man_key_1, content)

        management_keys, did_keys, services, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2, entry_3], chain_id_3
        )
        assert management_keys == {}
        assert did_keys == {}
        assert services == {}
        assert skipped_entries == 1

    def test_with_signature_from_management_key_with_partial_id(
        self, did, man_key_1, management_entry, deactivation_entry, chain_id
    ):
        entry_1 = management_entry({"managementKey": [man_key_1.to_entry_dict(did)]})
        entry_2 = deactivation_entry(
            did, man_key_1, ext_ids=["DIDDeactivation", "1.0.0", "#man-key-1"]
        )
        management_keys, _, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )

        assert len(management_keys) == 1
        assert skipped_entries == 1

    def test_with_malformed_management_key_id(
        self, did, man_key_1, management_entry, deactivation_entry, chain_id
    ):
        entry_1 = management_entry({"managementKey": [man_key_1.to_entry_dict(did)]})
        entry_2 = deactivation_entry(
            did,
            man_key_1,
            ext_ids=[
                "DIDDeactivation",
                "1.0.0",
                "did:fatcom:{}#man-key-1".format(chain_id),  # malformed
            ],
        )
        management_keys, _, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )

        assert len(management_keys) == 1
        assert skipped_entries == 1

    def test_with_non_matching_chain_id(
        self, did, man_key_1, management_entry, deactivation_entry, chain_id, chain_id_2
    ):
        entry_1 = management_entry({"managementKey": [man_key_1.to_entry_dict(did)]})
        entry_2 = deactivation_entry(
            did,
            man_key_1,
            ext_ids=[
                "DIDDeactivation",
                "1.0.0",
                "did:factom:{}#man-key-1".format(chain_id_2),
            ],
        )
        management_keys, _, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )

        assert len(management_keys) == 1
        assert skipped_entries == 1


class TestDIDVersionUpgradeEntry:
    def test_with_unknown_method_spec_version(
        self, did, man_key_1, management_entry, version_upgrade_entry, chain_id
    ):
        entry_1 = management_entry({"managementKey": [man_key_1.to_entry_dict(did)]})
        entry_2 = version_upgrade_entry(did, man_key_1, "0.4.0")
        entry_3 = version_upgrade_entry(did, man_key_1, "0.5.0")
        management_keys, _, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2, entry_3], chain_id
        )

        assert len(management_keys) == 1
        assert skipped_entries == 1

    def test_with_malformed_management_key_id(
        self, did, man_key_1, management_entry, version_upgrade_entry, chain_id
    ):
        entry_1 = management_entry({"managementKey": [man_key_1.to_entry_dict(did)]})
        entry_2 = version_upgrade_entry(
            did,
            man_key_1,
            "0.4.0",
            ext_ids=[
                "DIDMethodVersionUpgrade",
                "1.0.0",
                "did:fatcom:{}#man-key-1".format(chain_id),  # malformed
            ],
        )

        management_keys, _, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )

        assert len(management_keys) == 1
        assert skipped_entries == 1


class TestDIDUpdateEntry:
    def test_update_as_first_entry(
        self, did, man_key_1, service_1, update_entry, chain_id
    ):
        content = {"add": {"service": [service_1.to_entry_dict(did)]}}
        entry = update_entry(did, man_key_1, content)
        with pytest.raises(InvalidDIDChain) as excinfo:
            parse_did_chain_entries([entry], chain_id)

        assert str(excinfo.value) == "First entry must be of type DIDManagement"

    def test_update_with_invalid_signature(
        self, did, man_key_1, service_1, management_entry, update_entry, chain_id
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
        _, _, services, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )

        # Make sure the service hasn't been revoked
        assert len(services) == 1
        assert skipped_entries == 1

    def test_update_with_signature_from_key_with_insufficient_priority(
        self,
        did,
        man_key_1,
        man_key_3,
        service_2,
        management_entry,
        update_entry,
        chain_id,
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

        _, _, services, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )

        # Make sure the service hasn't been revoked
        assert len(services) == 1
        assert skipped_entries == 1

    def test_update_with_signature_from_did_key(
        self,
        did,
        man_key_1,
        did_key_1,
        service_1,
        management_entry,
        update_entry,
        chain_id,
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

        management_keys, did_keys, services, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )
        assert len(management_keys) == 1
        assert len(did_keys) == 1
        assert len(services) == 0
        assert skipped_entries == 1

    def test_update_with_signature_from_revoked_management_key(
        self,
        did,
        man_key_1,
        man_key_2,
        did_key_1,
        service_1,
        management_entry,
        update_entry,
        chain_id,
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

        management_keys, did_keys, services, _ = parse_did_chain_entries(
            [entry_1, entry_2, entry_3], chain_id
        )
        assert len(management_keys) == 1
        assert len(services) == 1
        assert len(did_keys) == 0

        assert man_key_2.alias not in management_keys

    def test_revocation_of_nonexistent_management_key(
        self, did, man_key_1, man_key_2, management_entry, update_entry, chain_id
    ):
        entry_1 = management_entry({"managementKey": [man_key_1.to_entry_dict(did)]})
        content = {"revoke": {"managementKey": [{"id": man_key_2.alias}]}}
        entry_2 = update_entry(did, man_key_1, content)

        management_keys, did_keys, services, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )

        assert len(management_keys) == 1
        assert man_key_1.alias in management_keys
        assert skipped_entries == 1

    def test_revocation_of_nonexistent_did_key(
        self,
        did,
        man_key_1,
        did_key_1,
        did_key_2,
        management_entry,
        update_entry,
        chain_id,
    ):
        entry_1 = management_entry(
            {
                "managementKey": [man_key_1.to_entry_dict(did)],
                "didKey": [did_key_1.to_entry_dict(did)],
            }
        )
        content = {"revoke": {"didKey": [{"id": did_key_2.alias}]}}
        entry_2 = update_entry(did, man_key_1, content)

        management_keys, did_keys, services, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )

        assert len(management_keys) == 1
        assert len(did_keys) == 1
        assert man_key_1.alias in management_keys
        assert did_key_1.alias in did_keys
        assert skipped_entries == 1

    def test_revocation_of_nonexistent_service(
        self,
        did,
        man_key_1,
        service_1,
        service_2,
        management_entry,
        update_entry,
        chain_id,
    ):
        entry_1 = management_entry(
            {
                "managementKey": [man_key_1.to_entry_dict(did)],
                "service": [service_1.to_entry_dict(did)],
            }
        )
        content = {"revoke": {"service": [{"id": service_2.alias}]}}
        entry_2 = update_entry(did, man_key_1, content)

        management_keys, did_keys, services, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )

        assert len(management_keys) == 1
        assert len(services) == 1
        assert man_key_1.alias in management_keys
        assert service_1.alias in services
        assert skipped_entries == 1

    def test_double_addition_of_management_key(
        self, did, man_key_1, man_key_2, management_entry, update_entry, chain_id
    ):
        entry_1 = management_entry({"managementKey": [man_key_1.to_entry_dict(did)]})
        content = {
            "add": {
                "managementKey": [
                    man_key_2.to_entry_dict(did),
                    man_key_2.to_entry_dict(did),
                ]
            }
        }
        entry_2 = update_entry(did, man_key_1, content)
        management_keys, _, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )
        assert len(management_keys) == 1
        assert man_key_1.alias in management_keys
        assert skipped_entries == 1

    def test_double_addition_of_did_key(
        self, did, man_key_1, did_key_1, management_entry, update_entry, chain_id
    ):
        entry_1 = management_entry({"managementKey": [man_key_1.to_entry_dict(did)]})
        content = {
            "add": {
                "didKey": [did_key_1.to_entry_dict(did), did_key_1.to_entry_dict(did)]
            }
        }
        entry_2 = update_entry(did, man_key_1, content)
        management_keys, did_keys, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )
        assert len(management_keys) == 1
        assert len(did_keys) == 0
        assert man_key_1.alias in management_keys
        assert skipped_entries == 1

    def test_double_addition_of_service(
        self, did, man_key_1, service_1, management_entry, update_entry, chain_id
    ):
        entry_1 = management_entry({"managementKey": [man_key_1.to_entry_dict(did)]})
        content = {
            "add": {
                "service": [service_1.to_entry_dict(did), service_1.to_entry_dict(did)]
            }
        }
        entry_2 = update_entry(did, man_key_1, content)
        management_keys, _, services, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )
        assert len(management_keys) == 1
        assert len(services) == 0
        assert man_key_1.alias in management_keys
        assert skipped_entries == 1

    def test_update_removing_all_management_keys_with_priority_zero(
        self, did, man_key_1, man_key_4, management_entry, update_entry, chain_id
    ):
        entry_1 = management_entry(
            {
                "managementKey": [
                    man_key_1.to_entry_dict(did),
                    man_key_4.to_entry_dict(did),
                ]
            }
        )
        content = {"revoke": {"managementKey": [{"id": man_key_1.alias}]}}
        entry_2 = update_entry(did, man_key_1, content)
        management_keys, _, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )
        assert len(management_keys) == 2
        assert skipped_entries == 1

    def test_update_after_unsuccessful_version_upgrade(
        self,
        did,
        man_key_1,
        man_key_2,
        management_entry,
        update_entry,
        version_upgrade_entry,
        chain_id,
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

        management_keys, _, _, _ = parse_did_chain_entries(
            [entry_1, entry_2, entry_3], chain_id
        )

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
        chain_id,
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

        management_keys, _, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2, entry_3], chain_id
        )

        assert len(management_keys) == 2
        assert skipped_entries == 1

    def test_intra_chain_replay_attack(
        self, did, man_key_1, service_1, management_entry, update_entry, chain_id
    ):
        entry_1 = management_entry({"managementKey": [man_key_1.to_entry_dict(did)]})
        content = {"add": {"service": [service_1.to_entry_dict(did)]}}
        entry_2 = update_entry(did, man_key_1, content)

        _, _, services, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )
        assert len(services) == 1
        assert skipped_entries == 0

        content = {"revoke": {"service": [{"id": service_1.alias}]}}
        entry_3 = update_entry(did, man_key_1, content)

        _, _, services, _ = parse_did_chain_entries(
            [entry_1, entry_2, entry_3], chain_id
        )
        assert len(services) == 0
        assert skipped_entries == 0

        # The repeated update entry should be ignored
        entry_4 = entry_2
        management_keys, _, services, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2, entry_3, entry_4], chain_id
        )

        assert len(management_keys) == 1
        # Check that the service wasn't added again
        assert len(services) == 0
        assert skipped_entries == 1

    def test_revocation_with_custom_priority_requirement(
        self,
        full_did,
        man_key_1,
        man_key_3,
        man_key_4,
        management_entry,
        update_entry,
        chain_id_3,
    ):
        entry_1 = management_entry(
            {
                "managementKey": [
                    man_key_1.to_entry_dict(full_did),
                    man_key_3.to_entry_dict(full_did),
                    man_key_4.to_entry_dict(full_did),
                ]
            }
        )
        content = {"revoke": {"managementKey": [{"id": man_key_4.alias}]}}
        entry_2 = update_entry(full_did, man_key_3, content)
        management_keys, _, _, _ = parse_did_chain_entries(
            [entry_1, entry_2], chain_id_3
        )

        assert len(management_keys) == 2
        assert man_key_1.alias in management_keys
        assert man_key_3.alias in management_keys

    def test_update_with_invalid_number_of_ext_ids(
        self, did, man_key_1, man_key_2, management_entry, update_entry, chain_id
    ):
        entry_1 = management_entry(
            {
                "managementKey": [
                    man_key_1.to_entry_dict(did),
                    man_key_2.to_entry_dict(did),
                ]
            }
        )
        content = {"revoke": {"managementKey": [{"id": man_key_1.alias}]}}
        entry_2 = update_entry(did, man_key_1, content)
        entry_2["extids"] = entry_2["extids"][:-1]
        management_keys, _, _, _ = parse_did_chain_entries([entry_1, entry_2], chain_id)

        assert len(management_keys) == 2
        assert man_key_1.alias in management_keys
        assert man_key_2.alias in management_keys

    def test_multiple_valid_and_invalid_updates(
        self,
        did,
        man_key_1,
        man_key_2,
        man_key_3,
        man_key_4,
        did_key_1,
        did_key_2,
        service_1,
        service_2,
        management_entry,
        update_entry,
        chain_id,
    ):
        # Active after this entry:
        # management_keys: man_key_1
        entry_1 = management_entry({"managementKey": [man_key_1.to_entry_dict(did)]})

        # Active after this entry:
        # management_keys: man_key_1
        content = {}
        entry_2 = update_entry(did, man_key_1, content)
        entry_2["content"] = b"\xbb"
        management_keys, _, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )
        assert len(management_keys) == 1
        assert skipped_entries == 1

        # Active after this entry:
        # management_keys: man_key_1
        content = {"add": {"managementKey": [man_key_1.to_entry_dict(did)]}}
        entry_3 = update_entry(did, man_key_1, content)
        _, _, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2, entry_3], chain_id
        )
        assert skipped_entries == 2

        # Active after this entry:
        # management_keys: man_key_1, man_key_3
        content = {"add": {"managementKey": [man_key_3.to_entry_dict(did)]}}
        entry_4 = update_entry(did, man_key_1, content)
        management_keys, _, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2, entry_3, entry_4], chain_id
        )
        assert skipped_entries == 2
        assert len(management_keys) == 2
        assert man_key_1.alias in management_keys
        assert man_key_3.alias in management_keys

        # Active after this entry:
        # management_keys: man_key_1, man_key_2, man_key_4
        # did_keys: did_key_1, did_key_2
        # services: service_1, service_2
        content = {
            "add": {
                "managementKey": [
                    man_key_2.to_entry_dict(did),
                    man_key_4.to_entry_dict(did),
                ],
                "didKey": [did_key_1.to_entry_dict(did), did_key_2.to_entry_dict(did)],
                "service": [service_1.to_entry_dict(did), service_2.to_entry_dict(did)],
            },
            "revoke": {"managementKey": [{"id": man_key_3.alias}]},
        }
        entry_5 = update_entry(did, man_key_1, content)
        management_keys, did_keys, services, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2, entry_3, entry_4, entry_5], chain_id
        )
        assert skipped_entries == 2
        assert len(management_keys) == 3
        assert len(did_keys) == 2
        assert len(services) == 2
        assert all(
            [
                man_key_1.alias in management_keys,
                man_key_2.alias in management_keys,
                man_key_4.alias in management_keys,
            ]
        )
        assert all([did_key_1.alias in did_keys, did_key_2.alias in did_keys])
        assert all([service_1.alias in services, service_2.alias in services])

        # Active after this entry:
        # management_keys: man_key_1, man_key_2, man_key_4
        # did_keys: did_key_1
        # services: service_1, service_2
        content = {"revoke": {"didKey": [{"id": did_key_2.alias}]}}
        entry_6 = update_entry(did, man_key_4, content)
        management_keys, did_keys, services, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2, entry_3, entry_4, entry_5, entry_6], chain_id
        )
        assert skipped_entries == 2
        assert len(management_keys) == 3
        assert len(did_keys) == 1
        assert len(services) == 2
        assert all(
            [
                man_key_1.alias in management_keys,
                man_key_2.alias in management_keys,
                man_key_4.alias in management_keys,
            ]
        )
        assert did_key_1.alias in did_keys
        assert all([service_1.alias in services, service_2.alias in services])

    def test_readdition_of_old_management_key(
        self, did, man_key_1, man_key_2, management_entry, update_entry, chain_id
    ):
        entry_1 = management_entry(
            {
                "managementKey": [
                    man_key_1.to_entry_dict(did),
                    man_key_2.to_entry_dict(did),
                ]
            }
        )
        content = {"revoke": {"managementKey": [{"id": man_key_2.alias}]}}
        entry_2 = update_entry(did, man_key_2, content)
        content = {"add": {"managementKey": [man_key_2.to_entry_dict(did)]}}
        entry_3 = update_entry(did, man_key_1, content)
        management_keys, _, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2, entry_3], chain_id
        )

        assert skipped_entries == 1
        assert len(management_keys) == 1
        assert man_key_1.alias in management_keys

    def test_readdition_of_old_did_key(
        self, did, man_key_1, did_key_1, management_entry, update_entry, chain_id
    ):
        entry_1 = management_entry(
            {
                "managementKey": [man_key_1.to_entry_dict(did)],
                "didKey": [did_key_1.to_entry_dict(did)],
            }
        )
        content = {"revoke": {"didKey": [{"id": did_key_1.alias}]}}
        entry_2 = update_entry(did, man_key_1, content)
        content = {"add": {"didKey": [did_key_1.to_entry_dict(did)]}}
        entry_3 = update_entry(did, man_key_1, content)
        management_keys, did_keys, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2, entry_3], chain_id
        )

        assert skipped_entries == 1
        assert len(management_keys) == 1
        assert len(did_keys) == 0

    def test_with_adding_management_key_from_another_chain(
        self, did, did_2, man_key_1, man_key_5, management_entry, update_entry, chain_id
    ):
        entry_1 = management_entry({"managementKey": [man_key_1.to_entry_dict(did)]})
        content = {"add": {"managementKey": [man_key_5.to_entry_dict(did_2)]}}
        entry_2 = update_entry(did, man_key_1, content)
        management_keys, _, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )

        assert skipped_entries == 1
        assert len(management_keys) == 1

    def test_with_revocation_of_management_key_from_another_chain(
        self, did, did_2, man_key_1, man_key_5, management_entry, update_entry, chain_id
    ):
        entry_1 = management_entry(
            {
                "managementKey": [
                    man_key_1.to_entry_dict(did),
                    man_key_5.to_entry_dict(did),
                ]
            }
        )
        # We try to revoke the same key added above, but with its chain referencing the chain of did_2
        content = {"revoke": {"managementKey": [{"id": man_key_5.full_id(did_2)}]}}
        entry_2 = update_entry(did, man_key_1, content)
        management_keys, _, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )

        assert skipped_entries == 1
        assert len(management_keys) == 2

    def test_with_signature_from_management_key_from_another_chain(
        self, did, did_2, man_key_1, did_key_1, management_entry, update_entry, chain_id
    ):
        entry_1 = management_entry({"managementKey": [man_key_1.to_entry_dict(did)]})
        content = {"add": {"didKey": [did_key_1.to_entry_dict(did)]}}
        # This will generate a signing from man_key_1, but the key identifier for the management key will reference the
        # chain ID of did_2. This means that the DIDUpdate entry should be skipped and no DID keys should be added, as
        # the signature for a DIDUpdate entry must be coming from a management key in the same chain
        entry_2 = update_entry(did_2, man_key_1, content)
        management_keys, did_keys, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )

        assert len(management_keys) == 1
        assert len(did_keys) == 0
        assert skipped_entries == 1

    def test_with_signature_from_management_key_with_partial_id(
        self, did, man_key_1, did_key_1, management_entry, update_entry, chain_id
    ):
        entry_1 = management_entry({"managementKey": [man_key_1.to_entry_dict(did)]})
        content = {"add": {"didKey": [did_key_1.to_entry_dict(did)]}}
        entry_2 = update_entry(
            did, man_key_1, content, ["DIDUpdate", "1.0.0", "man-key-1"]
        )
        management_keys, did_keys, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )

        assert len(management_keys) == 1
        assert len(did_keys) == 0
        assert skipped_entries == 1

    def test_with_adding_testnet_key_to_a_mainnet_did(
        self,
        did_mainnet,
        did_testnet,
        man_key_1,
        did_key_1,
        management_entry,
        update_entry,
        chain_id,
    ):
        entry_1 = management_entry(
            {"managementKey": [man_key_1.to_entry_dict(did_mainnet)]}
        )
        content = {"add": {"didKey": [did_key_1.to_entry_dict(did_testnet)]}}
        entry_2 = update_entry(did, man_key_1, content)
        management_keys, did_keys, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )

        assert len(management_keys) == 1
        assert len(did_keys) == 0
        assert skipped_entries == 1

    def test_with_adding_mainnet_key_to_a_mainnet_did(
        self,
        did_mainnet,
        man_key_1,
        did_key_1,
        management_entry,
        update_entry,
        chain_id,
    ):
        entry_1 = management_entry(
            {"managementKey": [man_key_1.to_entry_dict(did_mainnet)]}
        )
        content = {"add": {"didKey": [did_key_1.to_entry_dict(did_mainnet)]}}
        entry_2 = update_entry(did_mainnet, man_key_1, content)
        management_keys, did_keys, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )

        assert len(management_keys) == 1
        assert len(did_keys) == 1
        assert skipped_entries == 0

    def test_with_adding_testnet_key_to_a_testnet_did(
        self,
        did_testnet,
        man_key_1,
        did_key_1,
        management_entry,
        update_entry,
        chain_id,
    ):
        entry_1 = management_entry(
            {"managementKey": [man_key_1.to_entry_dict(did_testnet)]}
        )
        content = {"add": {"didKey": [did_key_1.to_entry_dict(did_testnet)]}}
        entry_2 = update_entry(did_testnet, man_key_1, content)
        management_keys, did_keys, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id, Network.Testnet
        )

        assert len(management_keys) == 1
        assert len(did_keys) == 1
        assert skipped_entries == 0

    def test_implicit_self_revocation(
        self,
        did,
        man_key_1,
        man_key_3,
        man_key_6,
        management_entry,
        update_entry,
        chain_id,
    ):
        entry_1 = management_entry(
            {
                "managementKey": [
                    man_key_1.to_entry_dict(did),
                    man_key_3.to_entry_dict(did),
                ]
            }
        )
        content = {"add": {"managementKey": [man_key_6.to_entry_dict(did)]}}
        entry_2 = update_entry(did, man_key_3, content)
        management_keys, _, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )

        assert len(management_keys) == 2
        assert "man-key-6" in management_keys and "man-key-1" in management_keys
        assert skipped_entries == 0

    def test_explicit_self_revocation(
        self,
        did,
        man_key_1,
        man_key_3,
        man_key_6,
        management_entry,
        update_entry,
        chain_id,
    ):
        entry_1 = management_entry(
            {
                "managementKey": [
                    man_key_1.to_entry_dict(did),
                    man_key_3.to_entry_dict(did),
                ]
            }
        )
        content = {
            "add": {"managementKey": [man_key_6.to_entry_dict(did)]},
            "revoke": {"managementKey": [{"id": man_key_3.alias}]},
        }
        entry_2 = update_entry(did, man_key_3, content)
        management_keys, _, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )

        assert len(management_keys) == 2
        assert "man-key-6" in management_keys and "man-key-1" in management_keys
        assert skipped_entries == 0

    def test_no_self_revocation_for_priority_zero_keys(
        self, did, man_key_1, man_key_2, management_entry, update_entry, chain_id
    ):
        entry_1 = management_entry({"managementKey": [man_key_1.to_entry_dict(did)]})
        content = {"add": {"managementKey": [man_key_2.to_entry_dict(did)]}}
        entry_2 = update_entry(did, man_key_1, content)
        management_keys, _, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )

        assert man_key_1.priority == 0
        assert len(management_keys) == 2
        assert "man-key-1" in management_keys and "man-key-2" in management_keys
        assert skipped_entries == 0

    def test_no_self_revocation_if_only_lower_priority_keys_are_added(
        self,
        did,
        man_key_1,
        man_key_3,
        man_key_4,
        management_entry,
        update_entry,
        chain_id,
    ):
        entry_1 = management_entry(
            {
                "managementKey": [
                    man_key_1.to_entry_dict(did),
                    man_key_3.to_entry_dict(did),
                ]
            }
        )

        content = {"add": {"managementKey": [man_key_4.to_entry_dict(did)]}}
        entry_2 = update_entry(did, man_key_3, content)
        management_keys, _, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )

        assert man_key_4.priority > man_key_3.priority
        assert len(management_keys) == 3
        assert (
            "man-key-1" in management_keys
            and "man-key-3" in management_keys
            and "man-key-4" in management_keys
        )
        assert skipped_entries == 0

    def test_ignore_update_if_multiple_keys_at_same_nonzero_priority_level_are_added(
        self, did, man_key_1, man_key_3, management_entry, update_entry, chain_id
    ):
        entry_1 = management_entry(
            {
                "managementKey": [
                    man_key_1.to_entry_dict(did),
                    man_key_3.to_entry_dict(did),
                ]
            }
        )

        new_man_key_1 = ManagementKey(
            alias="new-1",
            priority=1,
            controller=did,
            key_type=KeyType.EdDSA,
            priority_requirement=1,
        )

        new_man_key_2 = ManagementKey(
            alias="new-2",
            priority=1,
            controller=did,
            key_type=KeyType.EdDSA,
            priority_requirement=1,
        )

        content = {
            "add": {
                "managementKey": [
                    new_man_key_1.to_entry_dict(did),
                    new_man_key_2.to_entry_dict(did),
                ]
            }
        }
        entry_2 = update_entry(did, man_key_3, content)
        management_keys, _, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )

        assert new_man_key_1.priority == man_key_3.priority == new_man_key_2.priority
        assert skipped_entries == 1
        assert len(management_keys) == 2
        assert "man-key-1" in management_keys and "man-key-3" in management_keys

    def test_revocation_of_invalid_did_key_purpose(
        self, did, man_key_1, did_key_1, management_entry, update_entry, chain_id
    ):
        entry_1 = management_entry(
            {
                "managementKey": [man_key_1.to_entry_dict(did)],
                "didKey": [did_key_1.to_entry_dict(did)],
            }
        )
        content = {
            "revoke": {
                "didKey": [{"id": did_key_1.alias, "purpose": ["invalid_purpose"]}]
            }
        }
        entry_2 = update_entry(did, man_key_1, content)
        management_keys, did_keys, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )

        assert len(management_keys) == 1
        assert len(did_keys) == 1
        assert did_keys[did_key_1.alias].purpose == did_key_1.purpose
        assert skipped_entries == 1

    def test_revocation_of_nonexistent_did_key_purpose(
        self, did, man_key_1, did_key_1, management_entry, update_entry, chain_id
    ):
        entry_1 = management_entry(
            {
                "managementKey": [man_key_1.to_entry_dict(did)],
                "didKey": [did_key_1.to_entry_dict(did)],
            }
        )
        content = {
            "revoke": {
                "didKey": [
                    # did_key_1 has an authentication key purpose
                    {"id": did_key_1.alias, "purpose": [DIDKeyPurpose.PublicKey.value]}
                ]
            }
        }
        entry_2 = update_entry(did, man_key_1, content)
        management_keys, did_keys, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )

        assert len(management_keys) == 1
        assert len(did_keys) == 1
        assert did_keys[did_key_1.alias].purpose == did_key_1.purpose
        assert skipped_entries == 1

    def test_revocation_of_all_did_key_purposes(
        self, did, man_key_1, did_key_2, management_entry, update_entry, chain_id
    ):
        entry_1 = management_entry(
            {
                "managementKey": [man_key_1.to_entry_dict(did)],
                "didKey": [did_key_2.to_entry_dict(did)],
            }
        )
        content = {
            "revoke": {
                "didKey": [
                    {
                        "id": did_key_2.alias,
                        "purpose": [
                            DIDKeyPurpose.AuthenticationKey.value,
                            DIDKeyPurpose.PublicKey.value,
                        ],
                    }
                ]
            }
        }
        entry_2 = update_entry(did, man_key_1, content)
        management_keys, did_keys, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )

        assert len(management_keys) == 1
        assert len(did_keys) == 0
        assert skipped_entries == 0

    def test_revocation_with_duplicate_key_purposes_specified(
        self, did, man_key_1, did_key_1, management_entry, update_entry, chain_id
    ):
        entry_1 = management_entry(
            {
                "managementKey": [man_key_1.to_entry_dict(did)],
                "didKey": [did_key_1.to_entry_dict(did)],
            }
        )
        content = {
            "revoke": {
                "didKey": [
                    {
                        "id": did_key_1.alias,
                        "purpose": [
                            DIDKeyPurpose.AuthenticationKey.value,
                            DIDKeyPurpose.AuthenticationKey.value,
                        ],
                    }
                ]
            }
        }
        entry_2 = update_entry(did, man_key_1, content)
        management_keys, did_keys, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )

        assert len(management_keys) == 1
        assert len(did_keys) == 1
        assert did_keys[did_key_1.alias].purpose == did_key_1.purpose
        assert skipped_entries == 1

    def test_revocation_of_a_single_did_key_purpose(
        self, did, man_key_1, did_key_2, management_entry, update_entry, chain_id
    ):
        entry_1 = management_entry(
            {
                "managementKey": [man_key_1.to_entry_dict(did)],
                "didKey": [did_key_2.to_entry_dict(did)],
            }
        )
        content = {
            "revoke": {
                "didKey": [
                    {"id": did_key_2.alias, "purpose": [DIDKeyPurpose.PublicKey.value]}
                ]
            }
        }
        entry_2 = update_entry(did, man_key_1, content)
        management_keys, did_keys, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )

        assert len(management_keys) == 1
        assert len(did_keys) == 1
        assert did_keys[did_key_2.alias].purpose == [DIDKeyPurpose.AuthenticationKey]
        assert skipped_entries == 0

    def test_revocation_of_purpose_and_entire_key_in_same_entry(
        self, did, man_key_1, did_key_2, management_entry, update_entry, chain_id
    ):
        entry_1 = management_entry(
            {
                "managementKey": [man_key_1.to_entry_dict(did)],
                "didKey": [did_key_2.to_entry_dict(did)],
            }
        )
        content = {
            "revoke": {
                "didKey": [
                    {"id": did_key_2.alias, "purpose": [DIDKeyPurpose.PublicKey.value]},
                    {"id": did_key_2.alias},
                ]
            }
        }
        entry_2 = update_entry(did, man_key_1, content)
        management_keys, did_keys, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )

        assert len(management_keys) == 1
        assert len(did_keys) == 0
        assert skipped_entries == 0

    def test_multiple_did_key_revocations(
        self,
        did,
        man_key_1,
        did_key_1,
        did_key_2,
        management_entry,
        update_entry,
        chain_id,
    ):
        entry_1 = management_entry(
            {
                "managementKey": [man_key_1.to_entry_dict(did)],
                "didKey": [did_key_1.to_entry_dict(did), did_key_2.to_entry_dict(did)],
            }
        )
        content = {
            "revoke": {
                "didKey": [
                    {"id": did_key_2.alias, "purpose": [DIDKeyPurpose.PublicKey.value]},
                    {"id": did_key_1.alias},
                ]
            }
        }
        entry_2 = update_entry(did, man_key_1, content)
        management_keys, did_keys, _, skipped_entries = parse_did_chain_entries(
            [entry_1, entry_2], chain_id
        )

        assert len(management_keys) == 1
        assert len(did_keys) == 1
        assert did_keys[did_key_2.alias].purpose == [DIDKeyPurpose.AuthenticationKey]
        assert skipped_entries == 0
