import hashlib
import math
from packaging import version

from client.constants import DID_METHOD_SPEC_V020, ENTRY_SCHEMA_V100
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

    return min(lambda key: key.priority, orig_management_keys) == 0


def process_did_management_entry(
    ext_ids, content, method_version, management_keys, did_keys, services
):
    # Store the new management_keys, did_keys and services in separate objects, instead of
    # modifying the original ones directly. This ensures that if an exception occurs during
    # the processing of the entry, the original values will not be modified.
    new_management_keys = {}
    new_did_keys = {}
    new_services = {}

    if method_version == DID_METHOD_SPEC_V020 and ext_ids[1] == ENTRY_SCHEMA_V100:
        if not content["managementKey"]:
            raise MalformedDIDManagementEntry(
                "DIDManagement entry must contain at least one management key with priority 0"
            )
        found_key_with_priority_zero = False
        for key in content["managementKey"]:
            new_management_keys[get_alias(key["id"])] = ManagementKey.from_entry_dict(
                key
            )
            if key["priority"] == 0:
                found_key_with_priority_zero = True
        if not found_key_with_priority_zero:
            raise MalformedDIDManagementEntry(
                "DIDManagement entry must contain at least one management key with priority 0"
            )

        for key in content.get("didKey", []):
            new_did_keys[get_alias(key["id"])] = DIDKey.from_entry_dict(key)
        for service in content.get("service", []):
            new_services[get_alias(service["id"])] = Service.from_entry_dict(service)
    else:
        # Intentionally left blank, to be used for future support of other
        # DID method and entry schema versions
        pass

    # Only change the original keys & services if the processing of the whole entry has been successful
    management_keys.update(new_management_keys)
    did_keys.update(new_did_keys)
    services.update(new_services)

    return True, method_version


def process_did_update_entry(
    ext_ids, content, method_version, management_keys, did_keys, services
):
    revoked_management_keys = set()
    revoked_did_keys = set()
    revoked_services = set()

    new_management_keys = {}
    new_did_keys = {}
    new_services = {}

    if method_version == DID_METHOD_SPEC_V020 and ext_ids[1] == ENTRY_SCHEMA_V100:
        signing_key = management_keys.get(get_alias(ext_ids[2]))

        if (not signing_key) or (not is_valid_signature(ext_ids, content, signing_key)):
            return True, method_version

        signing_key_required_priority = math.inf

        if "revoke" in content:
            for key_id in content["revoke"].get("managementKey", []):
                alias = get_alias(key_id)
                # TODO: How to handle duplicate key revocations. How to handle revocations of inactive keys.
                # Currently both are being ignored
                if alias in management_keys:
                    revoked_management_keys.add(alias)
                    if management_keys[alias].priority_requirement is not None:
                        signing_key_required_priority = min(
                            signing_key_required_priority,
                            management_keys[alias].priority_requirement,
                        )
                    else:
                        signing_key_required_priority = min(
                            signing_key_required_priority,
                            management_keys[alias].priority_requirement,
                        )

            for key_id in content["revoke"].get("didKey", []):
                alias = get_alias(key_id)
                # TODO: How to handle duplicate key revocations. How to handle revocations of inactive keys.
                # Currently both are being ignored
                if alias in did_keys:
                    revoked_did_keys.add(alias)
                    if did_keys[alias].priority_requirement is not None:
                        signing_key_required_priority = min(
                            signing_key_required_priority,
                            management_keys[alias].priority_requirement,
                        )

            for service_id in content["revoke"].get("services", []):
                alias = get_alias(service_id)
                # TODO: How to handle duplicate service revocations. How to handle revocations of inactive services.
                # Currently both are being ignored
                if alias in services:
                    revoked_services.add(alias)
                    if services[alias].priority_requirement is not None:
                        signing_key_required_priority = min(
                            signing_key_required_priority,
                            management_keys[alias].priority_requirement,
                        )
        if "add" in content:
            for key in content["add"].get("managementKey", []):
                new_management_keys[get_alias(key)] = ManagementKey.from_entry_dict(key)
                signing_key_required_priority = min(
                    signing_key_required_priority, key["priority"]
                )
            for key in content["add"].get("didKey", []):
                new_did_keys[get_alias(key)] = DIDKey.from_entry_dict(key)
            for service in content["add"].get("service", []):
                new_services[get_alias(service)] = Service.from_entry_dict(service)

        # Check that the management key used for the signature is of sufficient priority
        if signing_key.priority > signing_key_required_priority:
            # If not, return without applying the update
            return True, method_version

        # Make sure that if the update is applied there will be at least one management key with priority 0 left
        if not exists_management_key_with_priority_zero(
            management_keys, new_management_keys, revoked_management_keys
        ):
            # If not, return without applying the update
            return True, method_version

        # Apply the updates
        for alias in revoked_management_keys:
            del management_keys[alias]
        management_keys.update(new_management_keys)

        for alias in revoked_did_keys:
            del did_keys[alias]
        did_keys.update(new_did_keys)

        for alias in revoked_services:
            del services[alias]
        services.update(new_services)
    else:
        # Intentionally left blank, to be used for future support of other
        # DID method and entry schema versions
        pass

    return True, method_version


def process_did_deactivation_entry(
    ext_ids, content, method_version, management_keys, did_keys, services
):
    if method_version == DID_METHOD_SPEC_V020 and ext_ids[1] == ENTRY_SCHEMA_V100:
        # DIDDeactivation entry must be signed by an active management key of priority 0
        signing_key = management_keys.get(get_alias(ext_ids[2]))
        if (
            (not signing_key)
            or (signing_key.priority != 0)
            or (not is_valid_signature(ext_ids, content, signing_key))
        ):
            return True, method_version

        management_keys.clear()
        did_keys.clear()
        services.clear()
    else:
        # Intentionally left blank, to be used for future support of other
        # DID method and entry schema versions
        pass

    return False, method_version


def process_did_method_version_upgrade_entry(
    ext_ids, content, method_version, management_keys, did_keys, services
):
    new_method_version = method_version

    if method_version == DID_METHOD_SPEC_V020 and ext_ids[1] == ENTRY_SCHEMA_V100:
        signing_key = management_keys.get(get_alias(ext_ids[2]))
        if (
            signing_key
            and is_method_version_upgrade(method_version, content["didMethodVersion"])
            and is_valid_signature(ext_ids, content, signing_key)
        ):
            new_method_version = content["didMethodVersion"]
    else:
        # Intentionally left blank, to be used for future support of other
        # DID method and entry schema versions
        pass

    return True, new_method_version
