import codecs
import hashlib
import json
import os
import re

from encryptor import encrypt_keys
from enums import SignatureType, EntryType, PurposeType
from keys import generate_key_pair
from models import ManagementKeyModel, DidKeyModel, ServiceModel

__all__ = ['DID', 'SignatureType', 'PurposeType', 'ENTRY_SCHEMA_VERSION', 'DID_METHOD_SPEC_VERSION']

ENTRY_SCHEMA_VERSION = '1.0.0'
DID_METHOD_SPEC_VERSION = '0.1.0'
ENTRY_SIZE_LIMIT = 10275


class DID:
    def __init__(self):
        self.id = self._generate_id()
        self.management_keys = []
        self.did_keys = []
        self.services = []
        self.used_key_aliases = set()
        self.used_service_aliases = set()

    def add_management_key(self, alias, priority, signature_type=SignatureType.EdDSA.value, controller=None):
        """
        Creates a new management key for the DID.

        Parameters
        ----------
        alias: str
            A human-readable nickname for the key. It should be unique across the keys defined in the DID document.
        priority: number
            A positive integer showing the hierarchical level of the key. The key(s) with priority 1
            overrides any key with priority greater than 1.
        signature_type: SignatureType, optional (default is EdDSA)
            Identifies the type of signature to be used when creating the key.
        controller: str, optional (default is None)
            An entity that will be making the signatures. It must be a valid DID. If the argument is not passed in,
            the default value is used which is the current DID itself.
        """

        if not controller:
            controller = self.id

        self._validate_management_key_input_params(alias, priority, signature_type, controller)

        key_pair = generate_key_pair(signature_type)
        self.management_keys.append(ManagementKeyModel(alias, priority, signature_type, controller,
                                                       key_pair.public_key, key_pair.private_key))

    def add_did_key(self, alias, purpose, signature_type=SignatureType.EdDSA.value,
                    controller=None, priority_requirement=None):
        """
        Creates a new DID key for the DID.

        Parameters
        ----------
        alias: str
            A human-readable nickname for the key. It should be unique across the keys defined in the DID document.
        purpose: PurposeType[]
            A list of PurposeTypes showing what purpose(s) the key serves. (PublicKey, AuthenticationKey or both)
        signature_type: SignatureType, optional (default is EdDSA)
            Identifies the type of signature to be used when creating the key.
        controller: str, optional (default is None)
            An entity that will be making the signatures. It must be a valid DID. If the argument is not passed in,
            the default value is used which is the current DID itself.
        priority_requirement: number, optional (default is None)
            A positive integer showing the minimum hierarchical level a key must have in order to remove this key.
        """

        if not controller:
            controller = self.id

        self._validate_did_key_input_params(alias, set(purpose), signature_type, controller, priority_requirement)

        key_pair = generate_key_pair(signature_type)
        self.did_keys.append(DidKeyModel(alias, set(purpose), signature_type, controller,
                                         key_pair.public_key, key_pair.private_key, priority_requirement))

    def add_service(self, alias, service_type, endpoint, priority_requirement=None):
        """
        Adds a new service to the DID Document.

        Parameters
        ----------
        alias: str
            A human-readable nickname for the service endpoint. It should be unique across the services
            defined in the DID document.
        service_type: str
            Type of the service endpoint.
        endpoint: str
            A service endpoint may represent any type of service the subject wishes to advertise,
            including decentralized identity management services for further discovery,
            authentication, authorization, or interaction.
            The service endpoint must be a valid URL.
        priority_requirement: number, optional (default is None)
            A positive integer showing the minimum hierarchical level a key must have in order to remove this service.
        """

        self._validate_service_input_params(alias, service_type, endpoint, priority_requirement)
        self.services.append(ServiceModel(alias, service_type, endpoint, priority_requirement))

    def export_entry_data(self):
        """
        Exports content that can be recorded on-chain to create the DID.

        Returns
        -------
        dict
            A dictionary with the ExtIDs and entry content of strings used that are the header columns.

        Raises
        ------
        RuntimeError
            If the entry size exceeds the entry size limit.
        """

        entry_content = json.dumps(self._get_did_document())
        entry_type = EntryType.Create.value

        entry_size = self._calculate_entry_size(
            [self.nonce],
            [entry_type, ENTRY_SCHEMA_VERSION],
            entry_content)

        if entry_size > ENTRY_SIZE_LIMIT:
            raise RuntimeError('You have exceeded the entry size limit! Please remove some of your keys or services.')

        return {
            'ext_ids': [entry_type, ENTRY_SCHEMA_VERSION, self.nonce],
            'content': entry_content
        }

    def export_encrypted_keys(self, password):
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

        return encrypt_keys(self.management_keys + self.did_keys, password)

    def _get_did_document(self):
        """
        Builds a DID Document.

        Returns
        -------
        dict
            A dictionary with the DID Document properties.
        """

        management_keys = list(map(self._build_key_entry_object, self.management_keys))
        if len(management_keys) < 1:
            raise RuntimeError('The DID must have at least one management key.')

        did_document = {
            'didMethodVersion': DID_METHOD_SPEC_VERSION,
            'managementKey': management_keys
        }

        did_keys = list(map(self._build_key_entry_object, self.did_keys))
        if len(did_keys) > 0:
            did_document['didKey'] = did_keys

        services = list(map(self._build_service_entry_object, self.services))
        if len(services) > 0:
            did_document['service'] = services

        return did_document

    def _generate_id(self):
        """
        Generates a new DID Id.

        Returns
        -------
        str
            A DID Id.
        """

        self.nonce = codecs.encode(os.urandom(32), 'hex').decode()
        chain_id = self._calculate_chain_id([EntryType.Create.value, ENTRY_SCHEMA_VERSION, self.nonce])
        did_id = 'did:factom:{}'.format(chain_id)
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

        public_key_property = 'publicKeyPem' if key.signature_type == SignatureType.RSA.value else 'publicKeyBase58'

        key_entry_object = {
            'id': '{}#{}'.format(self.id, key.alias),
            'type': '{}VerificationKey'.format(key.signature_type),
            'controller': key.controller,
            public_key_property: str(key.public_key, 'utf8')
        }

        if type(key) == ManagementKeyModel:
            key_entry_object['priority'] = key.priority
        else:
            key_entry_object['purpose'] = list(key.purpose)

            if key.priority_requirement is not None:
                key_entry_object['priorityRequirement'] = key.priority_requirement

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
            'id': '{}#{}'.format(self.id, service.alias),
            'type': service.service_type,
            'serviceEndpoint': service.endpoint
        }

        if service.priority_requirement is not None:
            service_entry_object['priorityRequirement'] = service.priority_requirement

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

        ext_ids_hash_bytes = bytearray(b'')
        for ext_id in ext_ids:
            ext_ids_hash_bytes.extend(hashlib.sha256(bytes(ext_id, 'utf-8')).digest())

        return hashlib.sha256(ext_ids_hash_bytes).hexdigest()

    def _validate_management_key_input_params(self, alias, priority, signature_type, controller):
        """
        Validates management key input parameters.

        Parameters
        ----------
        alias: str
        priority: number
        signature_type: SignatureType
        controller: str
        """

        if priority < 1:
            raise ValueError('Priority must be a positive integer.')

        self._validate_key_input_params(alias, signature_type, controller)

    def _validate_did_key_input_params(self, alias, purpose, signature_type, controller, priority_requirement):
        """
        Validates did key input parameters.

        Parameters
        ----------
        alias: str
        purpose: set
        signature_type: SignatureType
        controller: str
        priority_requirement: number
        """

        for purpose_type in purpose:
            if purpose_type not in (PurposeType.PublicKey.value, PurposeType.AuthenticationKey.value):
                raise ValueError('Purpose must contain only valid PurposeTypes.')

        if priority_requirement is not None and priority_requirement < 1:
            raise ValueError('Priority requirement must be a positive integer.')

        self._validate_key_input_params(alias, signature_type, controller)

    def _validate_key_input_params(self, alias, signature_type, controller):
        """
        Validates key input parameters.

        Parameters
        ----------
        alias: str
        signature_type: SignatureType
        controller: str
        """

        if not re.match("^[a-z0-9-]{1,32}$", alias):
            raise ValueError('Alias must not be more than 32 characters long and must contain only lower-case '
                             'letters, digits and hyphens.')

        if alias in self.used_key_aliases:
            raise ValueError('The given key alias "{}" has already been used.'.format(alias))

        self.used_key_aliases.add(alias)

        if signature_type not in (SignatureType.ECDSA.value, SignatureType.EdDSA.value, SignatureType.RSA.value):
            raise ValueError('Type must be a valid signature type.')

        if not re.match("^did:factom:[a-f0-9]{64}$", controller):
            raise ValueError('Controller must be a valid DID.')

    def _validate_service_input_params(self, alias, service_type, endpoint, priority_requirement):
        """
        Validates service input parameters.

        Parameters
        ----------
        alias: str
        service_type: str
        endpoint: str
        priority_requirement: number
        """

        if not re.match("^[a-z0-9-]{1,32}$", alias):
            raise ValueError('Alias must not be more than 32 characters long and must contain only lower-case '
                             'letters, digits and hyphens.')

        if alias in self.used_service_aliases:
            raise ValueError('The given service alias "{}" has already been used.'.format(alias))

        self.used_service_aliases.add(alias)

        if len(service_type) == 0:
            raise ValueError('Type is required.')

        if not re.match("^(http|https):\/\/(\w+:{0,1}\w*@)?(\S+)(:[0-9]+)?(\/|\/([\w#!:.?+=&%@!\-\/]))?$", endpoint):
            raise ValueError('Endpoint must be a valid URL address starting with http:// or https://.')

        if priority_requirement is not None and priority_requirement < 1:
            raise ValueError('Priority requirement must be a positive integer.')

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
        number
            A total size of the entry in bytes.
        """

        total_entry_size = 0
        fixed_header_size = 35
        total_entry_size += fixed_header_size + 2*len(hex_ext_ids) + 2*len(utf8_ext_ids)

        for ext_id in hex_ext_ids:
            total_entry_size += len(ext_id) / 2

        for ext_id in utf8_ext_ids:
            total_entry_size += len(bytes(ext_id, 'utf-8'))

        total_entry_size += len(bytes(content, 'utf-8'))
        return total_entry_size
