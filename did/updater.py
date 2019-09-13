from did.did import SignatureType


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
        self.orig_management_keys = self.did.management_keys.copy()
        self.orig_did_keys = self.did.did_keys.copy()
        self.orig_services = self.did.services.copy()

    def add_management_key(
        self,
        alias,
        priority,
        signature_type=SignatureType.EdDSA,
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
        Adds a management key to the DID object.

        Parameters
        ----------
        alias: str
        purpose: did.enums.PurposeType
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
        pass

    @staticmethod
    def _revoke(l, criteria):
        return list(filter(criteria, l))
