import json
from json import JSONDecodeError

from jsonschema.exceptions import ValidationError

from client.constants import ENTRY_SCHEMA_V100
from client.enums import EntryType
from resolver.entry_processors import (
    process_did_deactivation_entry_v100,
    process_did_management_entry_v100,
    process_did_method_version_upgrade_entry_v100,
    process_did_update_entry_v100,
)
from resolver.exceptions import (
    InvalidDIDChain,
    MalformedDIDManagementEntry,
    UnknownDIDMethodSpecVersion,
)
from resolver.schema import get_schema_validator
from resolver.validators import (
    validate_did_deactivation_ext_ids_v100,
    validate_did_management_ext_ids_v100,
    validate_did_method_version_upgrade_ext_ids_v100,
    validate_did_update_ext_ids_v100,
    EmptyEntryContentValidator,
)


DID_MANAGEMENT_SCHEMA = "did_management_entry.json"
DID_UPDATE_SCHEMA = "did_update_entry.json"
DID_METHOD_VERSION_UPGRADE_SCHEMA = "did_method_version_upgrade_entry.json"

ENTRY_SCHEMA_VALIDATORS = {
    ENTRY_SCHEMA_V100: {
        EntryType.Create.value: get_schema_validator(DID_MANAGEMENT_SCHEMA),
        EntryType.Update.value: get_schema_validator(DID_UPDATE_SCHEMA),
        EntryType.VersionUpgrade.value: get_schema_validator(
            DID_METHOD_VERSION_UPGRADE_SCHEMA
        ),
        # Since the DIDDeactivation entry is only valid if its content is empty,
        # a simple custom validator is used instead of a JSON schema one
        EntryType.Deactivation.value: EmptyEntryContentValidator,
    }
}

ENTRY_EXT_ID_VALIDATORS = {
    ENTRY_SCHEMA_V100: {
        EntryType.Create.value: validate_did_management_ext_ids_v100,
        EntryType.Update.value: validate_did_update_ext_ids_v100,
        EntryType.VersionUpgrade.value: validate_did_method_version_upgrade_ext_ids_v100,
        EntryType.Deactivation.value: validate_did_deactivation_ext_ids_v100,
    }
}

ENTRY_PROCESSORS = {
    ENTRY_SCHEMA_V100: {
        EntryType.Create.value: process_did_management_entry_v100,
        EntryType.Update.value: process_did_update_entry_v100,
        EntryType.VersionUpgrade.value: process_did_method_version_upgrade_entry_v100,
        EntryType.Deactivation.value: process_did_deactivation_entry_v100,
    }
}


def parse_did_chain_entries(entries):
    # Dictionaries from aliases to key or service objects
    management_keys = {}
    did_keys = {}
    services = {}

    # The current DID method version of the DID chain. This will be set, when parsing the first entry (provided that
    # it is a valid DIDManagement entry)
    method_version = None

    keep_parsing = True
    skipped_entries = 0
    processed_entries = 0

    # TODO: Add checks for entry uniqueness to avoid intra-chain replay attacks
    for i, entry in enumerate(entries):
        if not keep_parsing:
            # TODO: Return DID document, total entries processed, skipped entries
            return management_keys, did_keys, services

        processed_entries += 1

        ext_ids = entry["extids"]
        binary_content = entry["content"]

        # The first entry must be a valid DIDManagement entry
        if i == 0:
            try:
                parsed_content = json.loads(binary_content.decode())
                entry_type = ext_ids[0].decode()
                schema_version = ext_ids[1].decode()
                ENTRY_EXT_ID_VALIDATORS[schema_version][entry_type](ext_ids)
                ENTRY_SCHEMA_VALIDATORS[schema_version][entry_type].validate(
                    parsed_content
                )
                keep_parsing, method_version = ENTRY_PROCESSORS[schema_version][
                    entry_type
                ](
                    ext_ids,
                    binary_content,
                    parsed_content,
                    method_version,
                    management_keys,
                    did_keys,
                    services,
                )
            except (UnicodeDecodeError, JSONDecodeError) as e:
                raise InvalidDIDChain("DIDManagement entry content must be valid JSON")
            except KeyError:
                raise InvalidDIDChain("Unknown schema version or entry type")
            except IndexError:
                raise InvalidDIDChain("DIDManagement entry has insufficient ExtIDs")
            except ValidationError:
                raise InvalidDIDChain("Invalid DIDManagement entry content")
            except MalformedDIDManagementEntry as e:
                raise InvalidDIDChain(
                    "Malformed DIDManagement entry: {}".format(e.args[0])
                )
            # TODO: This can be replaced by an enum value check in the JSON schema
            except UnknownDIDMethodSpecVersion as e:
                raise InvalidDIDChain(
                    "Unknown DID method spec version: {}".format(e.args[0])
                )
        # Subsequent entries are valid only if:
        # * they have at least 4 ExtIDs
        # * they are a DIDUpdate, DIDDeactivation or DIDMethodVersionUpgrade entry of a known
        #   schema version
        # * their ExtIDs and content are well-formed
        #
        # Note that we don't need to raise an exception if any of the entries following
        # the first one are invalid. We can just ignore them, hence why also the ExtID
        # validators for these entries return a boolean, in contrast to the DIDManagement
        # ExtID validator, which raises an exception in case of malformed ExtIDs. The content
        # validators are instances of jsonschema.validator and they do raise an exception, which
        # is ignored
        elif len(ext_ids) >= 4:
            try:
                entry_type = ext_ids[0].decode()
                schema_version = ext_ids[1].decode()
                if (
                    entry_type == EntryType.Create.value
                    or schema_version not in ENTRY_SCHEMA_VALIDATORS
                    or entry_type not in ENTRY_SCHEMA_VALIDATORS[schema_version]
                    or not ENTRY_EXT_ID_VALIDATORS[schema_version][entry_type](ext_ids)
                ):
                    continue
                parsed_content = json.loads(binary_content.decode())
                ENTRY_SCHEMA_VALIDATORS[schema_version][entry_type].validate(
                    parsed_content
                )
                keep_parsing, method_version = ENTRY_PROCESSORS[schema_version][
                    entry_type
                ](
                    ext_ids,
                    binary_content,
                    parsed_content,
                    method_version,
                    management_keys,
                    did_keys,
                    services,
                )
            except (UnicodeDecodeError, JSONDecodeError, ValidationError):
                continue
        # Skip all other entries
        else:
            skipped_entries += 1

    # TODO: Return DID document, total entries processed, skipped entries
    return management_keys, did_keys, services
