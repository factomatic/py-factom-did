"""Helper functions for parser.py which are used to update the currently active management and DID keys,
and services."""

import math
from packaging import version

from factom_did.client.constants import DID_METHOD_SPEC_V020
from factom_did.client.enums import DIDKeyPurpose, Network
from factom_did.client.keys.did import DIDKey
from factom_did.client.keys.management import ManagementKey
from factom_did.client.service import Service
from factom_did.resolver.exceptions import MalformedDIDManagementEntry
from factom_did.resolver.validators import (
    validate_management_key_id_against_chain_id,
    validate_id_against_network,
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
        if not validate_id_against_network(key_data["id"], network):
            raise MalformedDIDManagementEntry(
                "Invalid key identifier '{}' for network ID '{}'".format(
                    key_data["id"], network.value
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
        if not validate_id_against_network(key_data["id"], network):
            raise MalformedDIDManagementEntry(
                "Invalid key identifier '{}' for network ID '{}'".format(
                    key_data["id"], network.value
                )
            )
        alias = _get_alias(key_data["id"])
        if alias in new_did_keys:
            raise MalformedDIDManagementEntry("Duplicate DID key found")
        new_did_keys[alias] = DIDKey.from_entry_dict(key_data)
    for service_data in parsed_content.get("service", []):
        if not validate_id_against_network(service_data["id"], network):
            raise MalformedDIDManagementEntry(
                "Invalid service identifier '{}' for network ID '{}'".format(
                    service_data["id"], network.value
                )
            )
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
    did_key_purposes_to_revoke = dict()
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
            skip_entry, signing_key_required_priority = _process_management_key_revocations(
                parsed_content,
                signing_key_required_priority,
                management_keys_to_revoke,
                active_management_keys,
                chain_id,
                network,
            )
            if skip_entry:
                return True, method_version, skipped_entries + 1

            skip_entry, signing_key_required_priority = _process_did_key_revocations(
                parsed_content,
                signing_key_required_priority,
                did_keys_to_revoke,
                did_key_purposes_to_revoke,
                active_did_keys,
                network,
            )
            if skip_entry:
                return True, method_version, skipped_entries + 1

            skip_entry, signing_key_required_priority = _process_service_revocations(
                parsed_content,
                signing_key_required_priority,
                services_to_revoke,
                active_services,
                network,
            )
            if skip_entry:
                return True, method_version, skipped_entries + 1

        if "add" in parsed_content:
            skip_entry, signing_key_required_priority = _process_management_key_additions(
                parsed_content,
                signing_key_required_priority,
                new_management_keys,
                active_management_keys,
                all_keys,
                chain_id,
                network,
            )
            if skip_entry:
                return True, method_version, skipped_entries + 1

            skip_entry, signing_key_required_priority = _process_did_key_additions(
                parsed_content,
                signing_key_required_priority,
                new_did_keys,
                active_did_keys,
                all_keys,
                network,
            )
            if skip_entry:
                return True, method_version, skipped_entries + 1

            skip_entry = _process_service_additions(
                parsed_content, new_services, active_services, network
            )
            if skip_entry:
                return True, method_version, skipped_entries + 1

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

        # If a management key is adding a new management key at the same priority level, it should also be revoking
        # itself. The exception is priority level 0, where multiple keys can be added without a revocation. Furthermore,
        # for all priority levels except 0, a management key is allowed to add only one new management key at the same
        # level. If this rule is violated, the entire DIDUpdate entry is discarded. In addition, if there is no explicit
        # self-revocation of the management key, the resolver will automagically revoke the signing management key.
        skip_entry = _apply_self_revocation_rules(
            signing_key, new_management_keys, management_keys_to_revoke
        )
        if skip_entry:
            return True, method_version, skipped_entries + 1

        # Apply the updates
        for alias in management_keys_to_revoke:
            del active_management_keys[alias]
        active_management_keys.update(new_management_keys)

        for alias in did_keys_to_revoke:
            del active_did_keys[alias]
        active_did_keys.update(new_did_keys)

        for alias, revoked_purpose in did_key_purposes_to_revoke.items():
            key = active_did_keys[alias]
            new_purpose = (
                key.purpose[1] if key.purpose[0] == revoked_purpose else key.purpose[0]
            )
            key.purpose = [new_purpose]

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
    _network,
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
    _network: Network
        Unused

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
    _network,
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
    _network: Network
        Unused

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


def _process_management_key_revocations(
    entry_content,
    signing_key_required_priority,
    keys_to_revoke,
    active_keys,
    chain_id,
    network,
):
    for key in entry_content["revoke"].get("managementKey", []):
        alias = _get_alias(key["id"])
        if (
            not validate_management_key_id_against_chain_id(key["id"], chain_id)
            or not validate_id_against_network(key["id"], network)
            or alias not in active_keys
            or alias in keys_to_revoke
        ):
            return True, signing_key_required_priority

        keys_to_revoke.add(alias)
        if active_keys[alias].priority_requirement is not None:
            signing_key_required_priority = min(
                signing_key_required_priority, active_keys[alias].priority_requirement
            )
        else:
            signing_key_required_priority = min(
                signing_key_required_priority, active_keys[alias].priority
            )

    return False, signing_key_required_priority


def _process_did_key_revocations(
    entry_content,
    signing_key_required_priority,
    keys_to_revoke,
    key_purposes_to_revoke,
    active_keys,
    network,
):
    for key_data in entry_content["revoke"].get("didKey", []):
        alias = _get_alias(key_data["id"])
        # If:
        # * revocation of a non-existent key, or
        # * multiple revocations of the same key, or
        # * revocations of a DID key with a non-matching network identifier
        # are attempted ignore the entire DIDUpdate entry
        if (
            alias not in active_keys
            or alias in keys_to_revoke
            or not validate_id_against_network(key_data["id"], network)
        ):
            return True, signing_key_required_priority

        if "purpose" in key_data:
            purposes = key_data["purpose"]
            # If duplicate purposes are specified, ignore the entry
            if len(purposes) != len(set(purposes)):
                return True, signing_key_required_priority
            active_purposes = set(map(lambda p: p.value, active_keys[alias].purpose))
            valid_purposes = {
                DIDKeyPurpose.AuthenticationKey.value,
                DIDKeyPurpose.PublicKey.value,
            }
            for purpose in purposes:
                if purpose not in valid_purposes or purpose not in active_purposes:
                    return True, signing_key_required_priority
            # If all purposes are revoked, revoke the entire key
            if set(purposes) == active_purposes:
                keys_to_revoke.add(alias)
            # Otherwise, just revoke the specific purpose. Note, that due to the checks above, we should be guaranteed
            # that only a single purpose is being revoked
            else:
                assert len(purposes) == 1
                key_purposes_to_revoke[alias] = DIDKeyPurpose.from_str(purposes[0])
        else:
            if alias in key_purposes_to_revoke:
                del key_purposes_to_revoke[alias]
            keys_to_revoke.add(alias)

        if active_keys[alias].priority_requirement is not None:
            signing_key_required_priority = min(
                signing_key_required_priority, active_keys[alias].priority_requirement
            )

    return False, signing_key_required_priority


def _process_service_revocations(
    entry_content,
    signing_key_required_priority,
    services_to_revoke,
    active_services,
    network,
):
    for service in entry_content["revoke"].get("service", []):
        alias = _get_alias(service["id"])
        # If:
        # * revocation of a non-existent service, or
        # * multiple revocations of the same service, or
        # * revocations of a service with a non-matching network identifier
        # are attempted ignore the entire DIDUpdate entry
        if (
            alias not in active_services
            or alias in services_to_revoke
            or not validate_id_against_network(service["id"], network)
        ):
            return True, signing_key_required_priority

        services_to_revoke.add(alias)
        if active_services[alias].priority_requirement is not None:
            signing_key_required_priority = min(
                signing_key_required_priority,
                active_services[alias].priority_requirement,
            )

    return False, signing_key_required_priority


def _process_management_key_additions(
    entry_content,
    signing_key_required_priority,
    new_keys,
    active_keys,
    all_keys,
    chain_id,
    network,
):
    for key_data in entry_content["add"].get("managementKey", []):
        alias = _get_alias(key_data["id"])
        if (
            not validate_management_key_id_against_chain_id(key_data["id"], chain_id)
            or not validate_id_against_network(key_data["id"], network)
            or alias in new_keys
            or alias in active_keys
        ):
            return True, signing_key_required_priority
        new_management_key = ManagementKey.from_entry_dict(key_data)
        if new_management_key in all_keys:
            return True, signing_key_required_priority
        new_keys[alias] = new_management_key
        signing_key_required_priority = min(
            signing_key_required_priority, key_data["priority"]
        )

    return False, signing_key_required_priority


def _process_did_key_additions(
    entry_content,
    signing_key_required_priority,
    new_keys,
    active_keys,
    all_keys,
    network,
):
    for key_data in entry_content["add"].get("didKey", []):
        alias = _get_alias(key_data["id"])
        # If double-addition of the same key or addition of a key with a non-matching network identifier is
        # attempted, ignore the entire DIDUpdate entry
        if (
            alias in new_keys
            or alias in active_keys
            or not validate_id_against_network(key_data["id"], network)
        ):
            return True, signing_key_required_priority
        new_did_key = DIDKey.from_entry_dict(key_data)
        if new_did_key in all_keys:
            return True, signing_key_required_priority
        new_keys[alias] = new_did_key

    return False, signing_key_required_priority


def _process_service_additions(entry_content, new_services, active_services, network):
    for service_data in entry_content["add"].get("service", []):
        alias = _get_alias(service_data["id"])
        # If double-addition of the same service or addition of a service with a non-matching network identifier
        # is attempted, ignore the entire DIDUpdate entry
        if (
            alias in new_services
            or alias in active_services
            or not validate_id_against_network(service_data["id"], network)
        ):
            return True
        new_services[alias] = Service.from_entry_dict(service_data)

    return False


def _apply_self_revocation_rules(
    signing_key, new_management_keys, management_keys_to_revoke
):
    # A signing key of priority 0 can do whatever the fuck it wants
    if signing_key.priority == 0:
        return False

    num_same_priority_keys = len(
        list(
            filter(
                lambda k: k.priority == signing_key.priority,
                new_management_keys.values(),
            )
        )
    )

    if num_same_priority_keys == 0:
        return False
    if num_same_priority_keys > 1:
        return True

    # num_same_priority_keys is 1
    if signing_key.alias not in management_keys_to_revoke:
        management_keys_to_revoke.add(signing_key.alias)
        return False
