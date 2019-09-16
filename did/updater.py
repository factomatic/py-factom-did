from collections import defaultdict
import hashlib
import json
import math
import operator as op

from did.blockchain import calculate_entry_size, record_entry
from did.constants import ENTRY_SCHEMA_VERSION, ENTRY_SIZE_LIMIT
from did.did import SignatureType
from did.enums import EntryType


class DIDUpdater:
    """
    Facilitates the creation of an update entry for an existing DID.

    Provides support for adding and revoking management keys, DID keys and services.

    Attributes
    ==========
    did: did.did.DID
        The DID object to update
    """

    def __init__(self, did):
        self.did = did
        self.orig_management_keys = set(self.did.management_keys.copy())
        self.orig_did_keys = set(self.did.did_keys.copy())
        self.orig_services = set(self.did.services.copy())

    def get_updated(self):
        return self.did

    def add_management_key(
        self,
        alias,
        priority,
        signature_type=SignatureType.EdDSA.value,
        controller=None,
        priority_requirement=None,
    ):
        """
        Adds a management key to the DID object.

        Parameters
        ----------
        alias: str
        priority: int
        signature_type: SignatureType, optional
        controller: str, optional
        priority_requirement: int, optional
        """
        self.did.management_key(
            alias, priority, signature_type, controller, priority_requirement
        )
        return self

    def add_did_key(
        self,
        alias,
        purpose,
        signature_type=SignatureType.EdDSA.value,
        controller=None,
        priority_requirement=None,
    ):
        """
        Adds a DID key to the DID object.

        Parameters
        ----------
        alias: str
        purpose: did.enums.DIDKeyPurpose
        signature_type: SignatureType, optional
        controller: str, optional
        priority_requirement: int, optional
        """

        self.did.did_key(
            alias, purpose, signature_type, controller, priority_requirement
        )
        return self

    def add_service(self, alias, service_type, endpoint, priority_requirement=None):
        """
        Adds a service to the DID object.

        Parameters
        ----------
        alias: str
        service_type: str
        endpoint: str
        priority_requirement: int, optional
        """
        self.did.service(alias, service_type, endpoint, priority_requirement)
        return self

    def revoke_management_key(self, alias):
        """
        Revokes a management key from the DID object.

        Parameters
        ----------
        alias: str
            The alias of the key to be revoked
        """
        self.did.management_keys = self._revoke(
            self.did.management_keys, lambda key: key.alias == alias
        )
        return self

    def revoke_did_key(self, alias):
        """
        Revokes a DID key from the DID object.

        Parameters
        ----------
        alias: str
            The alias of the key to be revoked
        """
        self.did.did_keys = self._revoke(
            self.did.did_keys, lambda key: key.alias == alias
        )
        return self

    def revoke_service(self, alias):
        """
        Revokes a service from the DID object.

        Parameters
        ----------
        alias: str
            The alias of the service to be revoked
        """
        self.did.services = self._revoke(
            self.did.services, lambda service: service.alias == alias
        )
        return self

    def export_entry_data(self):
        """
        Constructs a signed DIDUpdate entry ready for recording on-chain.

        Returns
        -------

        Raises
        ------
        RuntimeError
            If a management key of sufficient priority is not available to sign the update.
        """

        revoked_management_keys, revoked_did_keys, revoked_services = (
            self._get_revoked()
        )
        new_management_keys, new_did_keys, new_services = self._get_new()

        # Entries in the "revoke" section of a DIDUpdate entry
        revoke_dict = defaultdict(list)

        # The required priority for the signing key of the DIDUpdate entry
        update_key_required_priority = math.inf

        for key in revoked_management_keys:
            revoke_dict["managementKey"].append({"id": key.alias})
            update_key_required_priority = self._get_required_key_priority_for_update(
                key, update_key_required_priority, lambda k: k.priority_requirement
            )
            update_key_required_priority = self._get_required_key_priority_for_update(
                key, update_key_required_priority, lambda k: k.priority
            )
        for key in revoked_did_keys:
            revoke_dict["didKey"].append({"id": key.alias})
            update_key_required_priority = self._get_required_key_priority_for_update(
                key, update_key_required_priority, lambda k: k.priority_requirement
            )
        for service in revoked_services:
            revoke_dict["service"].append({"id": service.alias})
            update_key_required_priority = self._get_required_key_priority_for_update(
                service, update_key_required_priority, lambda s: s.priority_requirement
            )

        # Entries in the "add" section of a DIDUpdate entry
        add_dict = defaultdict(list)
        for key in new_management_keys:
            add_dict["managementKey"].append(key.to_entry_dict(self.did.id))
            update_key_required_priority = self._get_required_key_priority_for_update(
                key, update_key_required_priority, lambda k: k.priority
            )
        for key in new_did_keys:
            add_dict["didKey"].append(key.to_entry_dict(self.did.id))
        for service in new_services:
            add_dict["service"].append(service.to_entry_dict(self.did.id))

        # If there is nothing to revoke or add, return None
        if not revoke_dict and not add_dict:
            return None

        # It is safe to access the first element of the sorted list of management keys as the DID.update method throws
        # if there are no management keys
        signing_key = sorted(self.orig_management_keys, key=op.attrgetter("priority"))[
            0
        ]

        if signing_key.priority > update_key_required_priority:
            raise RuntimeError(
                "The update requires a key with priority <= {}, but the highest priority "
                "key available is with priority {}".format(
                    update_key_required_priority, signing_key.priority
                )
            )

        entry_content_dict = {}
        if revoke_dict:
            entry_content_dict["revoke"] = revoke_dict
        if add_dict:
            entry_content_dict["add"] = add_dict

        entry_content = json.dumps(entry_content_dict)
        data_to_sign = "".join(
            [
                EntryType.Update.value,
                ENTRY_SCHEMA_VERSION,
                signing_key.full_id(self.did.id),
                entry_content,
            ]
        ).replace(" ", "")
        signature = signing_key.sign(
            hashlib.sha256(data_to_sign.encode("utf-8")).digest()
        )

        ext_ids = [
            EntryType.Update.value.encode("utf-8"),
            ENTRY_SCHEMA_VERSION.encode("utf-8"),
            signing_key.full_id(self.did.id).encode("utf-8"),
            signature,
        ]

        entry_size = calculate_entry_size(ext_ids, entry_content.encode("utf-8"))

        if entry_size > ENTRY_SIZE_LIMIT:
            raise RuntimeError(
                "You have exceeded the entry size limit! Please "
                "remove some of your keys or services."
            )

        return {"ext_ids": ext_ids, "content": entry_content.encode("utf-8")}

    def record_on_chain(self, factomd, walletd, ec_address, verbose=False):
        """
        Attempts to record the DIDUpdate entry on-chain.
        """
        record_entry(
            self.did.get_chain(),
            self.export_entry_data(),
            factomd,
            walletd,
            ec_address,
            verbose,
        )

    def _get_revoked(self):
        revoked_management_keys = self.orig_management_keys.difference(
            set(self.did.management_keys)
        )
        revoked_did_keys = self.orig_did_keys.difference(set(self.did.did_keys))
        revoked_services = self.orig_services.difference(set(self.did.services))

        return revoked_management_keys, revoked_did_keys, revoked_services

    def _get_new(self):
        new_management_keys = set(self.did.management_keys).difference(
            self.orig_management_keys
        )
        new_did_keys = set(self.did.did_keys).difference(self.orig_did_keys)
        new_services = set(self.did.services).difference(self.orig_services)

        return new_management_keys, new_did_keys, new_services

    @staticmethod
    def _get_required_key_priority_for_update(
        key_or_service, current_required_priority, priority_f
    ):
        required_priority = priority_f(key_or_service)
        if (
            required_priority is not None
            and required_priority < current_required_priority
        ):
            return required_priority
        else:
            return current_required_priority

    @staticmethod
    def _revoke(l, criteria):
        return list(filter(lambda x: not criteria(x), l))
