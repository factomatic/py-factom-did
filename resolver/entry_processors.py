import hashlib
import math
from packaging import version

from client.constants import DID_METHOD_SPEC_V020

from client.keys import ManagementKey, DIDKey
from client.service import Service
from resolver.exceptions import MalformedDIDManagementEntry


def is_valid_signature(ext_ids, content, signing_key):
    signed_data = bytearray()
    for i in range(3):
        signed_data.extend(ext_ids[i])
    signed_data.extend(content)
    return signing_key.verify(hashlib.sha256(signed_data).digest(), ext_ids[3])


def is_method_version_upgrade(current_version, new_version):
    return version.parse(current_version) < version.parse(new_version)


def get_alias(full_or_partial_id):
    # Note that this works for identifiers of all types currently described in the spec, i.e.:
    # 1. did:factom:f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b#management-2
    # 2. #inbox
    # 3. management-1
    # The function will return management-2, inbox and management-1, respectively
    return full_or_partial_id.split("#")[-1]


def exists_management_key_with_priority_zero(
    management_keys, new_management_keys, revoked_management_keys
):
    orig_management_keys = management_keys.copy()
    for alias in revoked_management_keys:
        del orig_management_keys[alias]
    orig_management_keys.update(new_management_keys)

    return min(map(lambda key: key.priority, orig_management_keys.values())) == 0


def process_did_management_entry_v100(
    parsed_content, management_keys, did_keys, services, skipped_entries
):
    # Store the new management_keys, did_keys and services in separate objects, instead of
    # modifying the original ones directly. This ensures that if an exception occurs during
    # the processing of the entry, the original values will not be modified.
    new_management_keys = {}
    new_did_keys = {}
    new_services = {}

    method_version = parsed_content["didMethodVersion"]

    found_key_with_priority_zero = False
    for key_data in parsed_content["managementKey"]:
        alias = get_alias(key_data["id"])
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
        alias = get_alias(key_data["id"])
        if alias in new_did_keys:
            raise MalformedDIDManagementEntry("Duplicate DID key found")
        new_did_keys[alias] = DIDKey.from_entry_dict(key_data)
    for service_data in parsed_content.get("service", []):
        alias = get_alias(service_data["id"])
        if alias in new_services:
            raise MalformedDIDManagementEntry("Duplicate service found")
        new_services[alias] = Service.from_entry_dict(service_data)

    # Only change the original keys & services if the processing of the whole entry has been successful
    management_keys.update(new_management_keys)
    did_keys.update(new_did_keys)
    services.update(new_services)

    return True, method_version, skipped_entries


def process_did_update_entry_v100(
    ext_ids,
    binary_content,
    parsed_content,
    method_version,
    management_keys,
    did_keys,
    services,
    skipped_entries,
    all_keys,
):
    management_keys_to_revoke = set()
    did_keys_to_revoke = set()
    services_to_revoke = set()

    new_management_keys = {}
    new_did_keys = {}
    new_services = {}

    if method_version == DID_METHOD_SPEC_V020:
        signing_key = management_keys.get(get_alias(ext_ids[2].decode()))
        if (not signing_key) or (
            not is_valid_signature(ext_ids, binary_content, signing_key)
        ):
            return True, method_version, skipped_entries + 1

        signing_key_required_priority = math.inf

        if "revoke" in parsed_content:
            for key in parsed_content["revoke"].get("managementKey", []):
                alias = get_alias(key["id"])
                # If revocation of a non-existent key or multiple revocations of the same key are attempted,
                # ignore the entire DIDUpdate entry
                if alias not in management_keys or alias in management_keys_to_revoke:
                    return True, method_version, skipped_entries + 1
                management_keys_to_revoke.add(alias)
                if management_keys[alias].priority_requirement is not None:
                    signing_key_required_priority = min(
                        signing_key_required_priority,
                        management_keys[alias].priority_requirement,
                    )
                else:
                    signing_key_required_priority = min(
                        signing_key_required_priority, management_keys[alias].priority
                    )

            for key in parsed_content["revoke"].get("didKey", []):
                alias = get_alias(key["id"])
                # If revocation of a non-existent key or multiple revocations of the same key are attempted,
                # ignore the entire DIDUpdate entry
                if alias not in did_keys or alias in did_keys_to_revoke:
                    return True, method_version, skipped_entries + 1
                did_keys_to_revoke.add(alias)
                if did_keys[alias].priority_requirement is not None:
                    signing_key_required_priority = min(
                        signing_key_required_priority,
                        did_keys[alias].priority_requirement,
                    )

            for service in parsed_content["revoke"].get("service", []):
                alias = get_alias(service["id"])
                # If revocation of a non-existent service or multiple revocations of the same service are attempted,
                # ignore the entire DIDUpdate entry
                if alias not in services or alias in services_to_revoke:
                    return True, method_version, skipped_entries + 1
                services_to_revoke.add(alias)
                if services[alias].priority_requirement is not None:
                    signing_key_required_priority = min(
                        signing_key_required_priority,
                        services[alias].priority_requirement,
                    )
        if "add" in parsed_content:
            for key_data in parsed_content["add"].get("managementKey", []):
                alias = get_alias(key_data["id"])
                # If double-addition of the same key is attempted, ignore the entire DIDUpdate entry
                if alias in new_management_keys or alias in management_keys:
                    return True, method_version, skipped_entries + 1
                new_management_key = ManagementKey.from_entry_dict(key_data)
                if new_management_key in all_keys:
                    return True, method_version, skipped_entries + 1
                new_management_keys[alias] = new_management_key
                signing_key_required_priority = min(
                    signing_key_required_priority, key_data["priority"]
                )
            for key_data in parsed_content["add"].get("didKey", []):
                alias = get_alias(key_data["id"])
                # If double-addition of the same key is attempted, ignore the entire DIDUpdate entry
                if alias in new_did_keys or alias in did_keys:
                    return True, method_version, skipped_entries + 1
                new_did_key = DIDKey.from_entry_dict(key_data)
                if new_did_key in all_keys:
                    return True, method_version, skipped_entries + 1
                new_did_keys[alias] = new_did_key
            for service_data in parsed_content["add"].get("service", []):
                alias = get_alias(service_data["id"])
                # If double-addition of the same service is attempted, ignore the entire DIDUpdate entry
                if alias in new_services or alias in services:
                    return True, method_version, skipped_entries + 1
                new_services[alias] = Service.from_entry_dict(service_data)

        # Check that the management key used for the signature is of sufficient priority
        if signing_key.priority > signing_key_required_priority:
            # If not, return without applying the update
            return True, method_version, skipped_entries + 1

        # Make sure that if the update is applied there will be at least one management key with priority 0 left
        if not exists_management_key_with_priority_zero(
            management_keys, new_management_keys, management_keys_to_revoke
        ):
            # If not, return without applying the update
            return True, method_version, skipped_entries + 1

        # Apply the updates
        for alias in management_keys_to_revoke:
            del management_keys[alias]
        management_keys.update(new_management_keys)

        for alias in did_keys_to_revoke:
            del did_keys[alias]
        did_keys.update(new_did_keys)

        for alias in services_to_revoke:
            del services[alias]
        services.update(new_services)
    else:
        skipped_entries += 1

    return True, method_version, skipped_entries


def process_did_deactivation_entry_v100(
    ext_ids,
    binary_content,
    _parsed_content,
    method_version,
    management_keys,
    did_keys,
    services,
    skipped_entries,
    _all_keys,
):
    if method_version == DID_METHOD_SPEC_V020:
        # DIDDeactivation entry must be signed by an active management key of priority 0
        signing_key = management_keys.get(get_alias(ext_ids[2].decode()))
        if (
            (not signing_key)
            or (signing_key.priority != 0)
            or (not is_valid_signature(ext_ids, binary_content, signing_key))
        ):
            return True, method_version, skipped_entries + 1

        management_keys.clear()
        did_keys.clear()
        services.clear()
    else:
        skipped_entries += 1

    return False, method_version, skipped_entries


def process_did_method_version_upgrade_entry_v100(
    ext_ids,
    binary_content,
    parsed_content,
    method_version,
    management_keys,
    _did_keys,
    _services,
    skipped_entries,
    _all_keys,
):
    new_method_version = method_version

    if method_version == DID_METHOD_SPEC_V020:
        signing_key = management_keys.get(get_alias(ext_ids[2].decode()))
        if (
            signing_key
            and is_method_version_upgrade(
                method_version, parsed_content["didMethodVersion"]
            )
            and is_valid_signature(ext_ids, binary_content, signing_key)
        ):
            new_method_version = parsed_content["didMethodVersion"]
        else:
            skipped_entries += 1
    else:
        skipped_entries += 1

    return True, new_method_version, skipped_entries
