"""Helper functions for parser.py which are used to update the currently active management and DID keys,
and services."""

import math
from packaging import version

from factom_did.client.constants import DID_METHOD_SPEC_V020
from factom_did.client.enums import Network
from factom_did.client.keys.did import DIDKey
from factom_did.client.keys.management import ManagementKey
from factom_did.client.service import Service
from factom_did.resolver.exceptions import MalformedDIDManagementEntry
from factom_did.resolver.validators import (
    validate_management_key_id_against_chain_id,
    validate_signature,
)


def _is_method_version_upgrade(current_version, new_version):
    """
    Checks if the new version is an upgrade over the current version

    Parameters
    ----------
    current_version: str
    new_version: str

    Returns
    -------
    bool
    """
    return version.parse(current_version) < version.parse(new_version)


def _get_alias(full_or_partial_id):
    """
    Returns the alias from a full or partial id

    Parameters
    ----------
    full_or_partial_id: str

    Returns
    -------
    str
    """
    # Note that this works for identifiers of all types currently described in the spec, i.e.:
    # 1. did:factom:f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b#management-2
    # 2. did:factom:mainnet:f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b#management-2
    # 2. #inbox
    # 3. management-1
    # The function will return management-2, inbox and management-1, respectively
    return full_or_partial_id.split("#")[-1]


def exists_management_key_with_priority_zero(
    active_management_keys, new_management_keys, management_keys_to_revoke
):
    """
    Checks if a management key of priority zero would be present if the management keys will be updated according
    to the given parameters.

    Parameters
    ----------
    active_management_keys: dict
        The currently active management keys
    new_management_keys: dict
        The management keys to be added
    management_keys_to_revoke: set
        The management keys to be revoked

    Returns
    -------
    bool
    """
    orig_management_keys = active_management_keys.copy()
    for alias in management_keys_to_revoke:
        del orig_management_keys[alias]
    orig_management_keys.update(new_management_keys)

    return min(map(lambda key: key.priority, orig_management_keys.values())) == 0


def process_did_management_entry_v100(
    chain_id,
    parsed_content,
    management_keys,
    did_keys,
    services,
    skipped_entries,
    network,
):
    """
    Extracts the management keys, DID keys and services from a DIDManagement entry.

    This method only does validation of the logic rules for a DIDManagement entry (e.g. that at least one management
    key with priority 0 is present). Thus, it must be called only with a parsed entry, which has already undergone
    validation checks for proper formatting of its ExtIDs and content.

    Parameters
    ----------
    chain_id: str
        The DIDManagement chain ID.
    parsed_content: dict
        The parsed DIDManagement entry.
    management_keys: dict
        Will be updated to contain the management keys found in the entry.
    did_keys: dict
        Will be updated to contain the DID keys found in the entry.
    services: dict
        Will be updated to contain the services found in the entry.
    skipped_entries: int
        Will be incremented by one in case the DIDManagement entry is not valid.
    network: Network
        The Factom network on which the DID is recorded

    Returns
    -------
    tuple
        3-tuple (bool, str, int). The first element signifies if the caller should continue parsing the chain; the
        second element contains the current DID method specification version; the third element contains the number
        of skipped entries in the DIDManagement chain.

    Raises
    ------
    MalformedDIDManagementEntry
        If the DIDManagement entry does not conform to the DID specification
    """
    # Store the new management_keys, did_keys and services in separate objects, instead of
    # modifying the original ones directly. This ensures that if an exception occurs during
    # the processing of the entry, the original values will not be modified.
    new_management_keys = {}
    new_did_keys = {}
    new_services = {}

    method_version = parsed_content["didMethodVersion"]

    found_key_with_priority_zero = False
    for key_data in parsed_content["managementKey"]:
        if not validate_management_key_id_against_chain_id(key_data["id"], chain_id):
            raise MalformedDIDManagementEntry(
                "Invalid key identifier '{}' for chain ID '{}'".format(
                    key_data["id"], chain_id
                )
            )
        alias = _get_alias(key_data["id"])
        if alias in new_management_keys:
            raise MalformedDIDManagementEntry("Duplicate management key found")
        new_management_keys[alias] = ManagementKey.from_entry_dict(key_data)
        if key_data["priority"] == 0:
            found_key_with_priority_zero = True
    if not found_key_with_priority_zero:
        raise MalformedDIDManagementEntry(
            "Entry must contain at least one management key with priority 0"
        )

    for key_data in parsed_content.get("didKey", []):
        alias = _get_alias(key_data["id"])
        if alias in new_did_keys:
            raise MalformedDIDManagementEntry("Duplicate DID key found")
        new_did_keys[alias] = DIDKey.from_entry_dict(key_data)
    for service_data in parsed_content.get("service", []):
        alias = _get_alias(service_data["id"])
        if alias in new_services:
            raise MalformedDIDManagementEntry("Duplicate service found")
        new_services[alias] = Service.from_entry_dict(service_data)

    # Only change the original keys & services if the processing of the whole entry has been successful
    management_keys.update(new_management_keys)
    did_keys.update(new_did_keys)
    services.update(new_services)

    return True, method_version, skipped_entries


def process_did_update_entry_v100(
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
):
    """
    Updates the management keys, DID keys and services based on the contents of the entry.

    This method only does validation of the logic rules for a DIDUpdate entry (e.g. that the signature is valid).
    Thus, it must be called only with a parsed entry, which has already undergone validation checks for proper
    formatting of its ExtIDs and content.

    Parameters
    ----------
    chain_id: str
        The DIDManagement chain ID.
    ext_ids: list
        The ExtIDs of the entry, as bytes.
    binary_content: bytes
        The raw entry content.
    parsed_content: dict
        The parsed DIDUpdate entry.
    method_version: str
        The current DID method spec version.
    active_management_keys: dict
        The currently active management keys. Will be updated to contain the management keys found in the entry.
    active_did_keys: dict
        The currently active DID keys. Will be updated to contain the DID keys found in the entry.
    active_services: dict
        The currently active services. Will be updated to contain the services found in the entry.
    skipped_entries: int
        The current number of skipped entries. Will be incremented by one in case the DIDManagement entry is not valid.
    all_keys: set
        The set of all management and DID keys that have been active at some point for the current DIDManagement chain.
    network: Network
        The Factom network on which the DID is recorded

    Returns
    -------
    tuple
        3-tuple (bool, str, int). The first element signifies if the caller should continue parsing the chain; the
        second element contains the current DID method specification version; the third element contains the number
        of skipped entries in the DIDManagement chain.
    """
    management_keys_to_revoke = set()
    did_keys_to_revoke = set()
    services_to_revoke = set()

    new_management_keys = {}
    new_did_keys = {}
    new_services = {}

    if method_version == DID_METHOD_SPEC_V020:
        key_id = ext_ids[2].decode()
        signing_key = active_management_keys.get(_get_alias(key_id))
        if (not signing_key) or (
            not validate_signature(ext_ids, binary_content, signing_key)
        ):
            return True, method_version, skipped_entries + 1

        signing_key_required_priority = math.inf

        if "revoke" in parsed_content:
            for key in parsed_content["revoke"].get("managementKey", []):
                if not validate_management_key_id_against_chain_id(key["id"], chain_id):
                    return True, method_version, skipped_entries + 1
                alias = _get_alias(key["id"])
                # If revocation of a non-existent key or multiple revocations of the same key are attempted,
                # ignore the entire DIDUpdate entry
                if (
                    alias not in active_management_keys
                    or alias in management_keys_to_revoke
                ):
                    return True, method_version, skipped_entries + 1
                management_keys_to_revoke.add(alias)
                if active_management_keys[alias].priority_requirement is not None:
                    signing_key_required_priority = min(
                        signing_key_required_priority,
                        active_management_keys[alias].priority_requirement,
                    )
                else:
                    signing_key_required_priority = min(
                        signing_key_required_priority,
                        active_management_keys[alias].priority,
                    )

            for key in parsed_content["revoke"].get("didKey", []):
                alias = _get_alias(key["id"])
                # If revocation of a non-existent key or multiple revocations of the same key are attempted,
                # ignore the entire DIDUpdate entry
                if alias not in active_did_keys or alias in did_keys_to_revoke:
                    return True, method_version, skipped_entries + 1
                did_keys_to_revoke.add(alias)
                if active_did_keys[alias].priority_requirement is not None:
                    signing_key_required_priority = min(
                        signing_key_required_priority,
                        active_did_keys[alias].priority_requirement,
                    )

            for service in parsed_content["revoke"].get("service", []):
                alias = _get_alias(service["id"])
                # If revocation of a non-existent service or multiple revocations of the same service are attempted,
                # ignore the entire DIDUpdate entry
                if alias not in active_services or alias in services_to_revoke:
                    return True, method_version, skipped_entries + 1
                services_to_revoke.add(alias)
                if active_services[alias].priority_requirement is not None:
                    signing_key_required_priority = min(
                        signing_key_required_priority,
                        active_services[alias].priority_requirement,
                    )
        if "add" in parsed_content:
            for key_data in parsed_content["add"].get("managementKey", []):
                if not validate_management_key_id_against_chain_id(
                    key_data["id"], chain_id
                ):
                    return True, method_version, skipped_entries + 1
                alias = _get_alias(key_data["id"])
                # If double-addition of the same key is attempted, ignore the entire DIDUpdate entry
                if alias in new_management_keys or alias in active_management_keys:
                    return True, method_version, skipped_entries + 1
                new_management_key = ManagementKey.from_entry_dict(key_data)
                if new_management_key in all_keys:
                    return True, method_version, skipped_entries + 1
                new_management_keys[alias] = new_management_key
                signing_key_required_priority = min(
                    signing_key_required_priority, key_data["priority"]
                )
            for key_data in parsed_content["add"].get("didKey", []):
                alias = _get_alias(key_data["id"])
                # If double-addition of the same key is attempted, ignore the entire DIDUpdate entry
                if alias in new_did_keys or alias in active_did_keys:
                    return True, method_version, skipped_entries + 1
                new_did_key = DIDKey.from_entry_dict(key_data)
                if new_did_key in all_keys:
                    return True, method_version, skipped_entries + 1
                new_did_keys[alias] = new_did_key
            for service_data in parsed_content["add"].get("service", []):
                alias = _get_alias(service_data["id"])
                # If double-addition of the same service is attempted, ignore the entire DIDUpdate entry
                if alias in new_services or alias in active_services:
                    return True, method_version, skipped_entries + 1
                new_services[alias] = Service.from_entry_dict(service_data)

        # Check that the management key used for the signature is of sufficient priority
        if signing_key.priority > signing_key_required_priority:
            # If not, return without applying the update
            return True, method_version, skipped_entries + 1

        # Make sure that if the update is applied there will be at least one management key with priority 0 left
        if not exists_management_key_with_priority_zero(
            active_management_keys, new_management_keys, management_keys_to_revoke
        ):
            # If not, return without applying the update
            return True, method_version, skipped_entries + 1

        # Apply the updates
        for alias in management_keys_to_revoke:
            del active_management_keys[alias]
        active_management_keys.update(new_management_keys)

        for alias in did_keys_to_revoke:
            del active_did_keys[alias]
        active_did_keys.update(new_did_keys)

        for alias in services_to_revoke:
            del active_services[alias]
        active_services.update(new_services)
    else:
        skipped_entries += 1

    return True, method_version, skipped_entries


def process_did_deactivation_entry_v100(
    _chain_id,
    ext_ids,
    binary_content,
    _parsed_content,
    method_version,
    active_management_keys,
    active_did_keys,
    active_services,
    skipped_entries,
    _all_keys,
    network,
):
    """
    Deactivates the DID by resetting the currently active management and DID keys, and services.

    This method only does validation of the logic rules for a DIDDeactivation entry (e.g. that the signature is valid).
    Thus, it must be called only with a parsed entry, which has already undergone validation checks for proper
    formatting of its ExtIDs and content.

    Parameters
    ----------
    _chain_id: str
        Unused
    ext_ids: list
        The ExtIDs of the entry, as bytes.
    binary_content: bytes
        The raw entry content.
    _parsed_content: dict
        Unused
    method_version: str
        The current DID method spec version.
    active_management_keys: dict
        The currently active management keys. Will be reset.
    active_did_keys: dict
        The currently active DID keys. Will be reset.
    active_services: dict
        The currently active services. Will be reset.
    skipped_entries: int
        The current number of skipped entries. Will be incremented by one in case the DIDManagement entry is not valid.
    _all_keys: set
        Unused
    network: Network
        The Factom network on which the DID is recorded

    Returns
    -------
    tuple
        3-tuple (bool, str, int). The first element signifies if the caller should continue parsing the chain; the
        second element contains the current DID method specification version; the third element contains the number
        of skipped entries in the DIDManagement chain.
    """
    if method_version == DID_METHOD_SPEC_V020:
        # DIDDeactivation entry must be signed by an active management key of priority 0
        key_id = ext_ids[2].decode()
        signing_key = active_management_keys.get(_get_alias(key_id))
        if (
            not signing_key
            or signing_key.priority != 0
            or (not validate_signature(ext_ids, binary_content, signing_key))
        ):
            return True, method_version, skipped_entries + 1

        active_management_keys.clear()
        active_did_keys.clear()
        active_services.clear()
    else:
        skipped_entries += 1

    return False, method_version, skipped_entries


def process_did_method_version_upgrade_entry_v100(
    _chain_id,
    ext_ids,
    binary_content,
    parsed_content,
    method_version,
    active_management_keys,
    _active_did_keys,
    _active_services,
    skipped_entries,
    _all_keys,
    network,
):
    """
    Upgrades the DID method version.

    This method only does validation of the logic rules for a DIDMethodVersionUpgrade entry (e.g. that the signature is
    valid). Thus, it must be called only with a parsed entry, which has already undergone validation checks for proper
    formatting of its ExtIDs and content.

    Parameters
    ----------
    _chain_id: str
        Unused
    ext_ids: list
        The ExtIDs of the entry, as bytes.
    binary_content: bytes
        The raw entry content.
    parsed_content: dict
        Unused
    method_version: str
        The current DID method spec version.
    active_management_keys: dict
        The currently active DID management keys.
    _active_did_keys: dict
        Unused
    _active_services: dict
        Unused
    skipped_entries: int
        The current number of skipped entries. Will be incremented by one in case the DIDManagement entry is not valid.
    _all_keys: set
        Unused
    network: Network
        The Factom network on which the DID is recorded

    Returns
    -------
    tuple
        3-tuple (bool, str, int). The first element signifies if the caller should continue parsing the chain; the
        second element contains the current DID method specification version; the third element contains the number
        of skipped entries in the DIDManagement chain.
    """
    new_method_version = method_version

    if method_version == DID_METHOD_SPEC_V020:
        key_id = ext_ids[2].decode()
        signing_key = active_management_keys.get(_get_alias(key_id))
        if (
            signing_key
            and _is_method_version_upgrade(
                method_version, parsed_content["didMethodVersion"]
            )
            and validate_signature(ext_ids, binary_content, signing_key)
        ):
            new_method_version = parsed_content["didMethodVersion"]
        else:
            skipped_entries += 1
    else:
        skipped_entries += 1

    return True, new_method_version, skipped_entries
