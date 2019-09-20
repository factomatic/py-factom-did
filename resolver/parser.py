from os.path import abspath, dirname, join

import jsonref
from jsonschema.validators import validator_for

from client.enums import EntryType
from resolver.exceptions import *


def validate_did_management_ext_ids(ext_ids):
    pass


def validate_did_update_ext_ids(ext_ids):
    pass


def validate_did_deactivation_ext_ids(ext_ids):
    pass


def validate_did_method_version_upgrade_ext_ids(ext_ids):
    pass


def process_did_management_entry(
    ext_ids, content, method_version, management_keys, did_keys, services
):
    return True, method_version


def process_did_update_entry(
    ext_ids, content, method_version, management_keys, did_keys, services
):
    return True, method_version


def process_did_deactivation_entry(
    ext_ids, content, method_version, management_keys, did_keys, services
):
    return False, method_version


def process_did_method_version_upgrade_entry(
    ext_ids, content, method_version, management_keys, did_keys, services
):
    new_method_version = method_version
    return True, new_method_version


def load_json_schema(filename, version):
    """Loads the given schema file"""

    relative_path = join("resolver", "schemas", version, filename)
    absolute_path = abspath(relative_path)

    base_path = dirname(absolute_path)
    base_uri = "file://{}/".format(base_path)

    with open(absolute_path) as schema_file:
        return jsonref.loads(schema_file.read(), base_uri=base_uri, jsonschema=True)


def get_schema_validator(schema_file, version="1.0.0"):
    schema = load_json_schema(schema_file, version)
    cls = validator_for(load_json_schema(schema))
    cls.check_schema(schema)
    return cls(schema)


class DeactivationEntryContentValidator:
    @staticmethod
    def validate(content):
        if content:
            raise MalformedDIDDeactivationEntry(
                "Malformed {} entry content".format(EntryType.Deactivation.value)
            )


SCHEMA_V1 = "1.0.0"
DID_MANAGEMENT_SCHEMA = "did_management_entry.json"
DID_UPDATE_SCHEMA = "did_update_entry.json"
DID_METHOD_VERSION_UPGRADE_SCHEMA = "did_method_version_upgrade_entry.json"

ENTRY_SCHEMA_VALIDATORS = {
    SCHEMA_V1: {
        EntryType.Create.value: get_schema_validator(DID_MANAGEMENT_SCHEMA),
        EntryType.Update.value: get_schema_validator(DID_UPDATE_SCHEMA),
        EntryType.VersionUpgrade.value: get_schema_validator(
            DID_METHOD_VERSION_UPGRADE_SCHEMA
        ),
        EntryType.Deactivation.value: DeactivationEntryContentValidator,
    }
}

ENTRY_EXT_ID_VALIDATORS = {
    SCHEMA_V1: {
        EntryType.Create.value: validate_did_management_ext_ids,
        EntryType.Update.value: validate_did_update_ext_ids,
        EntryType.VersionUpgrade.value: validate_did_method_version_upgrade_ext_ids,
        EntryType.Deactivation.value: validate_did_deactivation_ext_ids,
    }
}

ENTRY_PROCESSORS = {
    SCHEMA_V1: {
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

    for i, entry in enumerate(entries):
        if not keep_parsing:
            # TODO: Return DID document, total entries process, skipped entries
            return

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
            except MalformedDIDManagementEntry as e:
                raise InvalidDIDChain("{}: {}".format(type(e).__name__, e.args[0]))
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
        # the first one are invalid. We can just ignore them, hence why also the validators
        # for these entries return a boolean, in contrast to the DIDManagement entry
        # validators, which raise an exception in case of a malformed entry.
        elif (
            len(ext_ids) >= 4
            and ext_ids[0] != EntryType.Create.value
            and ext_ids[1] in ENTRY_SCHEMA_VALIDATORS
            and ext_ids[0] in ENTRY_SCHEMA_VALIDATORS[ext_ids[1]]
            and ENTRY_EXT_ID_VALIDATORS[ext_ids[1]][ext_ids[0]](ext_ids)
            and ENTRY_SCHEMA_VALIDATORS[ext_ids[1]][ext_ids[0]].validate(content)
        ):
            keep_parsing, method_version = ENTRY_PROCESSORS[ext_ids[1]][ext_ids[0]](
                ext_ids, content, method_version, management_keys, did_keys, services
            )
        # Skip all other entries
        else:
            skipped_entries += 1

    # TODO: Return DID document, total entries process, skipped entries
    return {}
