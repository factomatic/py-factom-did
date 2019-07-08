from factom import Factomd, FactomWalletd
from did import DID, SignatureType
from encryptor import decrypt_keys, decrypt_keys_from_ui_store

factomd = Factomd()
walletd = FactomWalletd()
fct_address = 'FA2jK2HcLnRdS94dEcU27rF3meoJfpUcZPSinpb7AwQvPRY6RL1Q'
ec_address = 'EC3VjuH17eACyP22WwxPcqcbnVkE8QSd1HJP7MXDJkgR3hvaPBhP'


def create_new_did():
    new_did = DID()
    new_did.add_public_key()
    new_did.add_public_key('mysecpkey', SignatureType.ECDSA.value)
    new_did.add_authentication_key('myauthkey', SignatureType.EdDSA.value)
    new_did.add_service('PhotoStreamService', 'https://myphoto.com', 'myphotoservice')
    return new_did


def record_did_on_chain():
    new_did = create_new_did()
    entry_data = new_did.export_entry_data()
    walletd.new_chain(factomd, entry_data['ext_ids'], entry_data['content'], ec_address=ec_address)
    print(entry_data)


def encrypt_and_decrypt_did_keys():
    new_did = create_new_did()
    encrypted_keys = new_did.export_encrypted_keys('1234')
    print('-----------------------------------Encrypted---------------------------------------')
    print(encrypted_keys)

    decrypted_keys = decrypt_keys(encrypted_keys, '1234')
    print('-----------------------------------Decrypted---------------------------------------')
    print(decrypted_keys)
    print(decrypted_keys[0]['alias'])


def decrypt_keys_from_ui():
    pw = '123qweASD!@#'
    salt = 'cChkzEf0dWzlnp1UqYOtJLbljr+yp7hsyEngrQXqF3g='
    vector = 'iktNUmPe/P2JaZbJJR0Mww=='
    ctx = '5od26bPl/Z+BxwCX9i5WSlGYymy2ltUmW5F6sV5K4DsGo05anopJCwj7m7RHCMCJcoUlFy8PBgkow5lZNnpJRPPC6bjn0euW3kVLtLecgWy/ryOQx3tOV8CuY6iITV8Akk9KBBqQHIja4ePaUWKRlZM1YL9tFbFivNAbEt1ueWHhNb6zln7zwnAWJbXTK4Tn4piFrADXksoQYdt6lfPJbCWFhyRSCtY/WJLKORaeQ8qywN4CTKBb92Ae2xT4upZBWXlEURutk45I8AXMIEKpIpZXSczhVb06qGruIV/z5dQQX8ngExjDo7HsDcgtew+wDbBc4JQAtT/duQfWvVGe8QQPiu06U6F5V8u209WXSNHj02Hm8Jqck6upqPlBNJAhWw+K9A=='

    decrypted_keys = decrypt_keys_from_ui_store(ctx, pw, salt, vector)
    print(decrypted_keys)
    print(decrypted_keys[0]['privateKey'])


record_did_on_chain()
