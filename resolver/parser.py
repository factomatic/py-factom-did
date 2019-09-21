from jsonschema.exceptions import ValidationError

from client.constants import ENTRY_SCHEMA_V100
from client.enums import EntryType
from resolver.entry_processors import (
    process_did_deactivation_entry,
    process_did_management_entry,
    process_did_method_version_upgrade_entry,
    process_did_update_entry,
)
from resolver.exceptions import InvalidDIDChain, MalformedDIDManagementEntry
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
        EntryType.Create.value: process_did_management_entry,
        EntryType.Update.value: process_did_update_entry,
        EntryType.VersionUpgrade.value: process_did_method_version_upgrade_entry,
        EntryType.Deactivation.value: process_did_deactivation_entry,
    }
}


def parse_did_chain_entries(entries):
    # Dictionaries from aliases to key objects
    management_keys = {}
    did_keys = {}
    services = {}

    # The current DID method version of the DID chain
    method_version = None

    keep_parsing = True
    skipped_entries = 0
    processed_entries = 0

    # TODO: Add checks for entry uniqueness to avoid intra-chain replay attacks
    for i, entry in enumerate(entries):
        if not keep_parsing:
            # TODO: Return DID document, total entries process, skipped entries
            return {}

        processed_entries += 1

        ext_ids = entry["ext_ids"]
        content = entry["content"]

        # The first entry must be a valid DIDManagement entry
        if i == 0:
            try:
                ENTRY_EXT_ID_VALIDATORS[ext_ids[1]][ext_ids[0]](ext_ids)
                ENTRY_SCHEMA_VALIDATORS[ext_ids[1]][ext_ids[0]].validate(content)
                keep_parsing, method_version = ENTRY_PROCESSORS[ext_ids[1]][ext_ids[0]](
                    ext_ids,
                    content,
                    method_version,
                    management_keys,
                    did_keys,
                    services,
                )
            except ValidationError:
                raise InvalidDIDChain("Invalid DIDManagement entry content")
            except MalformedDIDManagementEntry as e:
                raise InvalidDIDChain("{}".format(e.args[0]))
            except KeyError:
                raise InvalidDIDChain("Unknown schema version or entry type")
            except IndexError:
                raise InvalidDIDChain("DIDManagement entry has insufficient ExtIDs")
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
        elif (
            len(ext_ids) >= 4
            and ext_ids[0] != EntryType.Create.value
            and ext_ids[1] in ENTRY_SCHEMA_VALIDATORS
            and ext_ids[0] in ENTRY_SCHEMA_VALIDATORS[ext_ids[1]]
            and ENTRY_EXT_ID_VALIDATORS[ext_ids[1]][ext_ids[0]](ext_ids)  # bool
        ):
            try:
                ENTRY_SCHEMA_VALIDATORS[ext_ids[1]][ext_ids[0]].validate(content)
                keep_parsing, method_version = ENTRY_PROCESSORS[ext_ids[1]][ext_ids[0]](
                    ext_ids,
                    content,
                    method_version,
                    management_keys,
                    did_keys,
                    services,
                )
            except ValidationError:
                pass
        # Skip all other entries
        else:
            skipped_entries += 1

    # TODO: Return DID document, total entries process, skipped entries
    return {}
