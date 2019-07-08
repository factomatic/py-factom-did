import hashlib
import json
import re
import secrets
from encryptor import encrypt_keys
from enums import SignatureType, EntryType
from keys import generate_key_pair
from models import KeyModel, ServiceModel

__all__ = ['DID', 'SignatureType']

DID_METHOD_SPEC_VERSION = '1.0'
ENTRY_SIZE_LIMIT = 10275
DEFAULT_ALIAS = 'defaultpubkey'


class DID:
    def __init__(self):
        self.id = self._generate_id()
        self.public_keys = []
        self.authentication_keys = []
        self.services = []
        self.used_key_aliases = set()
        self.used_service_aliases = set()

    def add_public_key(self, alias=DEFAULT_ALIAS, type=SignatureType.EdDSA.value, controller=None):
        """
        adds new public key to public_keys array

        :type alias: str
        :type type: SignatureType
        :type controller: str
        """

        if not controller:
            controller = self.id

        self._validate_key_input_params(alias, type, controller)

        key_pair = generate_key_pair(type)
        key_model = KeyModel(alias, type, controller, key_pair.public_key, key_pair.private_key)
        self.public_keys.append(key_model)

    def add_authentication_key(self, alias, type=SignatureType.EdDSA.value, controller=None):
        """
        adds new authentication key to authentication_keys array

        :type alias: str
        :type type: SignatureType
        :type controller: str
        """

        if not controller:
            controller = self.id

        self._validate_key_input_params(alias, type, controller)

        key_pair = generate_key_pair(type)
        key_model = KeyModel(alias, type, controller, key_pair.public_key, key_pair.private_key)
        self.authentication_keys.append(key_model)

    def add_service(self, type, endpoint, alias):
        """
        adds new service to services array

        :type type: str
        :type endpoint: str
        :type alias: str
        """

        self._validate_service_input_params(type, endpoint, alias)

        service_model = ServiceModel(type, endpoint, alias)
        self.services.append(service_model)

    def export_entry_data(self):
        """
        returns data to build create entry
        """

        entry_content = json.dumps(self._get_did_document())
        entry_type = EntryType.Create.value

        entry_size = self._calculate_entry_size(
            [self.nonce],
            [entry_type, DID_METHOD_SPEC_VERSION],
            json.dumps(entry_content))

        if entry_size > ENTRY_SIZE_LIMIT:
            raise RuntimeError('You have exceeded the entry size limit! Please remove some of your keys or services.')

        return {
            'ext_ids': [entry_type, DID_METHOD_SPEC_VERSION, self.nonce],
            'content': entry_content
        }

    def export_encrypted_keys(self, password):
        """
        returns encrypted keys cipher text
        """

        return encrypt_keys(self.public_keys, password)

    def _get_did_document(self):
        """
        returns did document
        """

        public_keys = list(map(self._build_key_entry_object, self.public_keys))
        authentication_keys = list(map(self._build_key_entry_object, self.authentication_keys))
        services = list(map(self._build_service_entry_object, self.services))

        return {
            '@context': 'https://w3id.org/did/v1',
            'id': self.id,
            'publicKey': public_keys,
            'authentication': authentication_keys,
            'service': services
        }

    def _generate_id(self):
        """
        generates new did id

        :return: did_id: str
        """

        self.nonce = secrets.token_hex(32)
        chain_id = self._calculate_chain_id([EntryType.Create.value, DID_METHOD_SPEC_VERSION, self.nonce])
        did_id = 'did:fctr:' + chain_id
        return did_id

    def _build_key_entry_object(self, key):
        """
        builds a key object to include in an entry

        :type key: KeyModel
        """

        return {
            'id': '{}#{}'.format(self.id, key.alias),
            'type': key.type + 'VerificationKey',
            'controller': key.controller,
            'publicKeyBase58': str(key.public_key, 'utf8')
        }

    def _build_service_entry_object(self, service):
        """
        builds a key object to include in an entry

        :type service: ServiceModel
        """

        return {
            'id': '{}#{}'.format(self.id, service.alias),
            'type': service.type,
            'serviceEndpoint': service.endpoint
        }

    @staticmethod
    def _calculate_chain_id(ext_ids):
        """
        calculates chain id by hashing each extension id, joining the hashes into a byte array and hashing the array

        :type ext_ids: Array
        :return full_hash_hex: str
        """

        ext_ids_hash_bytes = bytearray(b'')
        for ext_id in ext_ids:
            ext_id_hash = hashlib.sha256()
            ext_id_hash.update(bytes(ext_id, 'utf8'))
            ext_ids_hash_bytes.extend(bytearray(ext_id_hash.digest()))

        full_hash = hashlib.sha256()
        full_hash.update(ext_ids_hash_bytes)
        full_hash_hex = full_hash.hexdigest()

        return full_hash_hex

    def _validate_key_input_params(self, alias, type, controller):
        """
         validates public and authentication key input parameters

         :type alias: str
         :type type: SignatureType
         :type controller: str
        """

        if not re.match("^[a-z0-9-]{1,32}$", alias):
            raise ValueError('Alias must not be more than 32 characters long and must contain only lower-case '
                             'letters, digits and hyphens.')

        if alias in self.used_key_aliases:
            raise ValueError('The given key alias "{}" has already been used.'.format(alias))

        self.used_key_aliases.add(alias)

        if type not in (SignatureType.ECDSA.value, SignatureType.EdDSA.value, SignatureType.RSA.value):
            raise ValueError('Type must be a valid SignatureType.')

        if not re.match("^did:fctr:[abcdef0-9]{64}$", controller):
            raise ValueError('Controller must be a valid DID.')

    def _validate_service_input_params(self, type, endpoint, alias):
        """
        validates public and authentication key input parameters

        :type type: str
        :type endpoint: str
        :type alias: str
        """

        if len(type) == 0:
            raise ValueError('Type is required.')

        if not re.match("^(http|https):\/\/(\w+:{0,1}\w*@)?(\S+)(:[0-9]+)?(\/|\/([\w#!:.?+=&%@!\-\/]))?$", endpoint):
            raise ValueError('Endpoint must be a valid URL address starting with http:// or https://.')

        if not re.match("^[a-z0-9-]{1,32}$", alias):
            raise ValueError('Alias must not be more than 32 characters long and must contain only lower-case '
                             'letters, digits and hyphens.')

        if alias in self.used_service_aliases:
            raise ValueError('The given service alias "{}" has already been used.'.format(alias))

        self.used_service_aliases.add(alias)

    @staticmethod
    def _calculate_entry_size(hex_ext_ids, utf8_ext_ids, content):
        """
        calculates entry size in bytes

        :type hex_ext_ids: Array
        :type utf8_ext_ids: Array
        :type content: str
        :return total_entry_size: number
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
