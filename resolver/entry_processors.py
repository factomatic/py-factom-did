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
