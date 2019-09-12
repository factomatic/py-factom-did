from base64 import urlsafe_b64encode
import codecs
import hashlib
import json
import os

from factom.exceptions import FactomAPIError

from did.encryptor import encrypt_keys
from did.enums import SignatureType, EntryType, PurposeType
from did.keys import ManagementKey, DIDKey
from did.service import Service

__all__ = [
    "DID",
    "SignatureType",
    "PurposeType",
    "ENTRY_SCHEMA_VERSION",
    "DID_METHOD_SPEC_VERSION",
    "DID_METHOD_NAME",
]

ENTRY_SCHEMA_VERSION = "1.0.0"
DID_METHOD_NAME = "did:factom"
DID_METHOD_SPEC_VERSION = "0.2.0"
ENTRY_SIZE_LIMIT = 10275


class DID:
    """
    Enables the construction of a DID document, by facilitating the construction of management keys and DID keys and the
    addition of services. Allows exporting of the resulting DID object into a format suitable for recording on the
    Factom blockchain.

    Provides encryption functionality of private keys for the DID and their export to a string or to a JSON file.

    Attributes
    ----------
    did: str, optional
        The decentralized identifier, a 32 byte hexadecimal string
    management_keys: ManagementKey[], optional
        A list of management keys
    did_keys: DIDKey[], optional
        A list of DID keys
    services: Service[], optional
        A list of services
    """

    def __init__(self, did=None, management_keys=None, did_keys=None, services=None):
        # TODO: Add validation logic for the did
        self.id = self._generate_did() if did is None else did
        self.management_keys = [] if management_keys is None else management_keys
        self.did_keys = [] if did_keys is None else did_keys
        self.services = [] if services is None else services

        self._used_key_aliases = set()
        self._used_service_aliases = set()

        for key in management_keys:
            self._used_key_aliases.add(key.alias)
        for key in did_keys:
            self._used_key_aliases.add(key.alias)
        for service in services:
            self._used_service_aliases.add(service)

    def management_key(
        self,
        alias,
        priority,
        signature_type=SignatureType.EdDSA.value,
        controller=None,
        priority_requirement=None,
    ):
        """
        Creates a new management key for the DID.

        Parameters
        ----------
        alias: str
            A human-readable nickname for the key. It should be unique across the keys defined in the DID document.
        priority: int
            A non-negative integer showing the hierarchical level of the key. Keys with lower priority
            override keys with higher priority.
        signature_type: SignatureType, optional
            Identifies the type of signature that the key pair can be used to generate and verify.
        controller: str, optional
            An entity that controls the key. It must be a valid DID. If the argument is not passed in,
            the default value is used which is the current DID itself.
        priority_requirement: int, optional
            A non-negative integer showing the minimum hierarchical level a key must have in order to remove this key.
        """

        if not controller:
            controller = self.id

        if alias in self._used_key_aliases:
            raise ValueError(
                'The given key alias "{}" has already been used.'.format(alias)
            )

        self._used_key_aliases.add(alias)

        self.management_keys.append(
            ManagementKey(
                alias, priority, signature_type, controller, priority_requirement
            )
        )

        return self

    def did_key(
        self,
        alias,
        purpose,
        signature_type=SignatureType.EdDSA.value,
        controller=None,
        priority_requirement=None,
    ):
        """
        Creates a new DID key for the DID.

        Parameters
        ----------
        alias: str
            A human-readable nickname for the key. It should be unique across the keys defined in the DID document.
        purpose: PurposeType[]
            A list of PurposeTypes showing what purpose(s) the key serves. (PublicKey, AuthenticationKey or both)
        signature_type: SignatureType, optional
            Identifies the type of signature to be used when creating the key.
        controller: str, optional
            An entity that will be making the signatures. It must be a valid DID. If the argument is not passed in,
            the default value is used which is the current DID itself.
        priority_requirement: int, optional
            A non-negative integer showing the minimum hierarchical level a key must have in order to remove this key.
        """

        if not controller:
            controller = self.id

        if alias in self._used_key_aliases:
            raise ValueError(
                'The given key alias "{}" has already been used.'.format(alias)
            )

        self._used_key_aliases.add(alias)

        self.did_keys.append(
            DIDKey(
                alias, set(purpose), signature_type, controller, priority_requirement
            )
        )

        return self

    def service(self, alias, service_type, endpoint, priority_requirement=None):
        """
        Adds a new service to the DID Document.

        Parameters
        ----------
        alias: str
            A human-readable nickname for the service endpoint. It should be unique across the services defined in the
            DID document.
        service_type: str
            Type of the service endpoint.
        endpoint: str
            A service endpoint may represent any type of service the subject wishes to advertise, including
            decentralized identity management services for further discovery, authentication, authorization, or
            interaction.
            The service endpoint must be a valid URL.
        priority_requirement: int, optional
            A non-negative integer showing the minimum hierarchical level a key must have in order to remove this
            service.
        """

        if alias in self._used_service_aliases:
            raise ValueError(
                'The given service alias "{}" has already been used.'.format(alias)
            )

        self._used_service_aliases.add(alias)

        self.services.append(
            Service(alias, service_type, endpoint, priority_requirement)
        )

        return self

    def export_entry_data(self):
        """
        Exports content that can be recorded on-chain to create the DID.

        Returns
        -------
        dict
            A dictionary with the ExtIDs and entry content of strings used that are the header columns.

        Raises
        ------
        ValueError
            If there are no management keys.
            If there is no management key with priority 0.
            If the entry size exceeds the entry size limit.
        """

        management_keys = list(map(self._build_key_entry_object, self.management_keys))

        if len(management_keys) < 1:
            raise ValueError("The DID must have at least one management key.")
        if not any(map(lambda key: key["priority"] == 0, management_keys)):
            raise ValueError("At least one management key must have priority 0.")

        entry_content = json.dumps(self._get_did_document())
        entry_type = EntryType.Create.value

        entry_size = self._calculate_entry_size(
            [self.nonce], [entry_type, ENTRY_SCHEMA_VERSION], entry_content
        )

        if entry_size > ENTRY_SIZE_LIMIT:
            raise ValueError(
                "You have exceeded the entry size limit! Please "
                "remove some of your keys or services."
            )

        return {
            "ext_ids": [entry_type, ENTRY_SCHEMA_VERSION, self.nonce],
            "content": entry_content,
        }

    def export_encrypted_keys_as_str(self, password):
        """
        Exports encrypted keys cipher text.

        Parameters
        ----------
        password: str
            A password to use for the encryption of the keys.

        Returns
        -------
        str
            Encrypted keys cipher text.
        """

        encryption_result = encrypt_keys(self.management_keys, self.did_keys, password)
        cipher_text_b64 = urlsafe_b64encode(
            encryption_result["salt"]
            + encryption_result["iv"]
            + encryption_result["data"]
        )
        return str(cipher_text_b64, "utf8")

    def export_encrypted_keys_as_json(self, password):
        """
        Exports encrypted keys as JSON.

        Parameters
        ----------
        password: str
            A password to use for the encryption of the keys.

        Returns
        -------
        str
            Encrypted keys JSON.
        """

        encryption_result = encrypt_keys(self.management_keys, self.did_keys, password)
        return json.dumps(
            {
                "data": str(urlsafe_b64encode(encryption_result["data"]), "utf8"),
                "encryptionAlgo": {
                    "name": "AES-GCM",
                    "iv": str(urlsafe_b64encode(encryption_result["iv"]), "utf8"),
                    "salt": str(urlsafe_b64encode(encryption_result["salt"]), "utf8"),
                    "tagLength": 128,
                },
                "did": self.id,
            }
        )

    def record_on_chain(self, factomd, walletd, ec_address, verbose=False):
        """
        Attempts to record the DID document on-chain.

        Parameters
        ----------
        factomd: obj
            Factomd instance, instantiated from the Python factom-api package.
        walletd: obj
            Factom walletd instance, instantiated from the Python factom-api package.
        ec_address: str
            EC address used to pay for the chain & entry creation.
        verbose: bool, optional
            If true, display the contents of the entry that will be recorded
            on-chain.

        Raises
        ------
            RuntimeError
                If the chain cannot be created
        """

        from pprint import pprint

        entry_data = self.export_entry_data()
        if verbose:
            pprint(entry_data)

        # Encode the entry data
        ext_ids = map(lambda x: x.encode("utf-8"), entry_data["ext_ids"])
        content = entry_data["content"].encode("utf-8")

        try:
            walletd.new_chain(factomd, ext_ids, content, ec_address=ec_address)
        except FactomAPIError as e:
            raise RuntimeError(
                "Failed while trying to record DID data on-chain: {}".format(e.data)
            )

    def _get_did_document(self):
        """
        Builds a DID Document.

        Returns
        -------
        dict
            A dictionary with the DID Document properties.
        """

        management_keys = list(map(self._build_key_entry_object, self.management_keys))

        did_document = {
            "didMethodVersion": DID_METHOD_SPEC_VERSION,
            "managementKey": management_keys,
        }

        did_keys = list(map(self._build_key_entry_object, self.did_keys))
        if len(did_keys) > 0:
            did_document["didKey"] = did_keys

        services = list(map(self._build_service_entry_object, self.services))
        if len(services) > 0:
            did_document["service"] = services

        return did_document

    def _generate_did(self):
        """
        Generates a new DID Id.

        Returns
        -------
        str
            A DID Id.
        """

        self.nonce = codecs.encode(os.urandom(32), "hex").decode()
        chain_id = self._calculate_chain_id(
            [EntryType.Create.value, ENTRY_SCHEMA_VERSION, self.nonce]
        )
        did_id = "{}:{}".format(DID_METHOD_NAME, chain_id)
        return did_id

    def _build_key_entry_object(self, key):
        """
        Builds a key object to include in the DID Document.

        Parameters
        ----------
        key: KeyModel
            A key to use when building the object.

        Returns
        -------
        obj
            A key object to include in the DID Document.
        """

        public_key_property = (
            "publicKeyPem"
            if key.signature_type == SignatureType.RSA.value
            else "publicKeyBase58"
        )

        key_entry_object = {
            "id": "{}#{}".format(self.id, key.alias),
            "type": "{}VerificationKey".format(key.signature_type),
            "controller": key.controller,
            public_key_property: str(key.public_key, "utf8"),
        }

        if type(key) == ManagementKey:
            key_entry_object["priority"] = key.priority
        else:
            key_entry_object["purpose"] = list(key.purpose)

        if key.priority_requirement is not None:
            key_entry_object["priorityRequirement"] = key.priority_requirement

        return key_entry_object

    def _build_service_entry_object(self, service):
        """
        Builds a service object to include in the DID Document.

        Parameters
        ----------
        service: ServiceModel
            A service to use when building the object.

        Returns
        -------
        obj
            A service object to include in the DID Document.
        """

        service_entry_object = {
            "id": "{}#{}".format(self.id, service.alias),
            "type": service.service_type,
            "serviceEndpoint": service.endpoint,
        }

        if service.priority_requirement is not None:
            service_entry_object["priorityRequirement"] = service.priority_requirement

        return service_entry_object

    @staticmethod
    def _calculate_chain_id(ext_ids):
        """
        Calculates chain id by hashing each ExtID, joining the hashes into a byte array and hashing the array.

        Parameters
        ----------
        ext_ids: list
            A list of ExtIds.

        Returns
        -------
        str
            A chain id.
        """

        ext_ids_hash_bytes = bytearray(b"")
        for ext_id in ext_ids:
            ext_ids_hash_bytes.extend(hashlib.sha256(bytes(ext_id, "utf-8")).digest())

        return hashlib.sha256(ext_ids_hash_bytes).hexdigest()

    @staticmethod
    def _calculate_entry_size(hex_ext_ids, utf8_ext_ids, content):
        """
        Calculates entry size in bytes.

        Parameters
        ----------
        hex_ext_ids: list
        utf8_ext_ids: list
        content: str

        Returns
        -------
        int
            A total size of the entry in bytes.
        """

        total_entry_size = 0
        fixed_header_size = 35
        total_entry_size += (
            fixed_header_size + 2 * len(hex_ext_ids) + 2 * len(utf8_ext_ids)
        )

        for ext_id in hex_ext_ids:
            total_entry_size += len(ext_id) / 2

        for ext_id in utf8_ext_ids:
            total_entry_size += len(bytes(ext_id, "utf-8"))

        total_entry_size += len(bytes(content, "utf-8"))
        return total_entry_size
