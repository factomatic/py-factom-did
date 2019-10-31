import json
from json import JSONDecodeError

from jsonschema.exceptions import ValidationError

from factom_did.client.constants import ENTRY_SCHEMA_V100
from factom_did.client.enums import EntryType, Network
from factom_did.resolver.entry_processors import (
    process_did_deactivation_entry_v100,
    process_did_management_entry_v100,
    process_did_method_version_upgrade_entry_v100,
    process_did_update_entry_v100,
)
from factom_did.resolver.exceptions import InvalidDIDChain, MalformedDIDManagementEntry
from factom_did.resolver.schema import get_schema_validator
from factom_did.resolver.validators import (
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


def parse_did_chain_entries(entries, chain_id, network=Network.Mainnet):
    """
    Attempts to parse the entries in a DIDManagement chain.

    Parameters
    ----------
    entries: list of dict
        A list of entries in the DIDManagement chain as returned by the Python factom-api library, or an equivalent
        API/library. Each element of the list is a dictionary, with keys 'content', 'extids' and 'entryhash' and the
        values are bytes
    chain_id: str
        The DIDManagement chain ID
    network: Network
        The Factom network on which the DID is recorded

    Returns
    -------
    tuple
        A 4-tuple containing the active management keys, the active DID key, the active services and the number of
        entries skipped while parsing the chain.

    Raises
    ------
    InvalidDIDChain
       If the first entry in the chain is not a valid DIDManagement entry
    """
    # Dictionaries from aliases to active key or service objects
    active_management_keys = {}
    active_did_keys = {}
    active_services = {}

    # The sets of all management and DID keys that have ever been active for the given DID chain
    all_keys = set()

    # Set of entry hashes that have already been processed
    processed_entry_hashes = set()

    # The current DID method version of the DID chain. This will be set, when parsing the first entry (provided that
    # it is a valid DIDManagement entry)
    method_version = None
    skipped_entries = 0
    keep_parsing = True

    for i, entry in enumerate(entries):
        if not keep_parsing:
            return (
                active_management_keys,
                active_did_keys,
                active_services,
                skipped_entries + len(entries) - i,
            )

        ext_ids = entry["extids"]
        binary_content = entry["content"]
        entry_hash = entry["entryhash"]

        # Do not allow intra-chain replay attacks
        if entry_hash in processed_entry_hashes:
            skipped_entries += 1
            continue
        processed_entry_hashes.add(entry_hash)

        # The first entry must be a valid DIDManagement entry
        if i == 0:
            try:
                entry_type = ext_ids[0].decode()
                if entry_type != EntryType.Create.value:
                    raise InvalidDIDChain("First entry must be of type DIDManagement")
                parsed_content = json.loads(binary_content.decode())
                schema_version = ext_ids[1].decode()
                ENTRY_EXT_ID_VALIDATORS[schema_version][entry_type](ext_ids)
                ENTRY_SCHEMA_VALIDATORS[schema_version][entry_type].validate(
                    parsed_content
                )
                keep_parsing, method_version, skipped_entries = ENTRY_PROCESSORS[
                    schema_version
                ][entry_type](
                    chain_id,
                    parsed_content,
                    active_management_keys,
                    active_did_keys,
                    active_services,
                    skipped_entries,
                    network,
                )
                all_keys.update(
                    active_management_keys.values(), active_did_keys.values()
                )
            except (UnicodeDecodeError, JSONDecodeError):
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
                    or not ENTRY_EXT_ID_VALIDATORS[schema_version][entry_type](
                        ext_ids, chain_id, network
                    )
                ):
                    skipped_entries += 1
                    continue
                decoded_content = binary_content.decode()
                parsed_content = decoded_content
                if entry_type != EntryType.Deactivation.value:
                    parsed_content = json.loads(decoded_content)
                ENTRY_SCHEMA_VALIDATORS[schema_version][entry_type].validate(
                    parsed_content
                )
                keep_parsing, method_version, skipped_entries = ENTRY_PROCESSORS[
                    schema_version
                ][entry_type](
                    chain_id,
                    ext_ids,
                    binary_content,
                    parsed_content,
                    method_version,
                    active_management_keys,
                    active_did_keys,
                    active_services,
                    skipped_entries,
                    all_keys,
                    network,
                )
                all_keys.update(
                    active_management_keys.values(), active_did_keys.values()
                )
            except (UnicodeDecodeError, JSONDecodeError, ValidationError):
                skipped_entries += 1
                continue
        # Skip all other entries, as they are not valid
        else:
            skipped_entries += 1

    return active_management_keys, active_did_keys, active_services, skipped_entries
