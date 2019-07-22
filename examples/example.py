from factom import Factomd, FactomWalletd

from did.did import DID, SignatureType, PurposeType
from did.encryptor import decrypt_keys_from_str, decrypt_keys_from_json, decrypt_keys_from_ui_store_file

factomd = Factomd()
walletd = FactomWalletd()
fct_address = 'FA2jK2HcLnRdS94dEcU27rF3meoJfpUcZPSinpb7AwQvPRY6RL1Q'
ec_address = 'EC3VjuH17eACyP22WwxPcqcbnVkE8QSd1HJP7MXDJkgR3hvaPBhP'


def create_new_did():
    new_did = DID()

    '''Add new management key with default signature type and controller'''
    management_key_1_alias = 'my-first-management-key'
    management_key_1_priority = 1
    new_did.add_management_key(management_key_1_alias, management_key_1_priority)

    '''Add new management key with specified signature type and controller'''
    management_key_2_alias = 'my-second-management-key'
    management_key_2_priority = 2
    management_key_2_signature_type = SignatureType.ECDSA.value
    management_key_2_controller = 'did:factom:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b8005'
    new_did.add_management_key(management_key_2_alias, management_key_2_priority, management_key_2_signature_type,
                               management_key_2_controller)

    '''Add new public key with default signature type and controller'''
    did_key_1_alias = 'my-did-key-1'
    did_key_1_purpose = [PurposeType.PublicKey.value]
    new_did.add_did_key(did_key_1_alias, did_key_1_purpose)

    '''Add new authentication key with specified signature type'''
    did_key_2_alias = 'my-did-key-2'
    did_key_2_purpose = [PurposeType.AuthenticationKey.value]
    did_key_2_signature_type = SignatureType.RSA.value
    new_did.add_did_key(did_key_2_alias, did_key_2_purpose, did_key_2_signature_type)

    '''Add new both public and authentication key with specified signature type, controller and priority requirement'''
    did_key_3_alias = 'my-did-key-3'
    did_key_3_purpose = [PurposeType.PublicKey.value, PurposeType.AuthenticationKey.value]
    did_key_3_signature_type = SignatureType.EdDSA.value
    did_key_3_controller = 'did:factom:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b8005'
    did_key_3_priority_requirement = 2
    new_did.add_did_key(did_key_3_alias, did_key_3_purpose, did_key_3_signature_type, did_key_3_controller,
                        did_key_3_priority_requirement)

    '''Add new service'''
    service_alias = 'my-photo-service'
    service_type = 'PhotoStreamService'
    service_endpoint = 'https://myphoto.com'
    new_did.add_service(service_alias, service_type, service_endpoint)

    return new_did


def record_did_on_chain():
    new_did = create_new_did()
    entry_data = new_did.export_entry_data()
    walletd.new_chain(factomd, entry_data['ext_ids'], entry_data['content'], ec_address=ec_address)
    print(entry_data)


def encrypt_keys_as_str_and_decrypt():
    new_did = create_new_did()
    keys_cipher_text = new_did.export_encrypted_keys_as_str('1234')
    print('-----------------------------------Encrypted---------------------------------------')
    print(keys_cipher_text)

    decrypted_keys = decrypt_keys_from_str(keys_cipher_text, '1234')
    print('-----------------------------------Decrypted---------------------------------------')
    print(decrypted_keys)
    print(decrypted_keys[0]['alias'])


def encrypt_keys_as_json_and_decrypt():
    new_did = create_new_did()
    keys_json = new_did.export_encrypted_keys_as_json('1234')
    print('-----------------------------------Encrypted---------------------------------------')
    print(keys_json)

    decrypted_keys = decrypt_keys_from_json(keys_json, '1234')
    print('-----------------------------------Decrypted---------------------------------------')
    print(decrypted_keys)
    print(decrypted_keys[0]['alias'])


def decrypt_keys_from_ui():
    '''
    Decrypt keys file downloaded from factom-did-ui app
    '''

    file_path = '.\\examples\\paper-did-UTC--2019-06-17T18_09_31.938Z.txt'
    password = '123qweASD!@#'
    decrypted_keys = decrypt_keys_from_ui_store_file(file_path, password)
    print(decrypted_keys)
    print(decrypted_keys[0]['privateKey'])


if __name__ == '__main__':
    record_did_on_chain()