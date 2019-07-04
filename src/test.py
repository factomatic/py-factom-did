import unittest
from did import DID, SignatureType
from encryptor import decrypt_keys, decrypt_keys_from_ui_store


class Did(unittest.TestCase):
    def test_generating_new_empty_did(self):
        new_did = DID()

        self.assertRegex(new_did.id, "^did:fctr:[abcdef0-9]{64}$")
        self.assertEqual(64, len(new_did.nonce))
        self.assertEqual([], new_did.public_keys)
        self.assertEqual([], new_did.authentication_keys)
        self.assertEqual([], new_did.services)


class PublicKeys(unittest.TestCase):
    def test_add_default_public_key(self):
        new_did = DID()
        new_did.add_public_key()
        generated_pub_key = new_did.public_keys[0]

        self.assertEqual(1, len(new_did.public_keys))
        self.assertEqual('defaultpubkey', generated_pub_key.alias)
        self.assertEqual('Ed25519', generated_pub_key.type)
        self.assertEqual(new_did.id, generated_pub_key.controller)

    def test_add_public_keys(self):
        new_did = DID()

        public_key_alias = 'my-public-key-1'
        public_key_signature_type = SignatureType.ECDSA.value
        public_key_controller = 'did:fctr:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b8005'
        new_did.add_public_key(public_key_alias, public_key_signature_type, public_key_controller)
        generated_pub_key = new_did.public_keys[0]

        second_public_key_alias = 'my-public-key-2'
        second_public_key_signature_type = SignatureType.RSA.value
        second_public_key_controller = 'did:fctr:7fefbb2cf9a51a0479b705f0e67530925680d2bc2ba2e2eecfa62b90f8e51c1f'
        new_did.add_public_key(second_public_key_alias, second_public_key_signature_type, second_public_key_controller)
        second_generated_pub_key = new_did.public_keys[1]

        self.assertEqual(2, len(new_did.public_keys))
        self.assertEqual(public_key_alias, generated_pub_key.alias)
        self.assertEqual(public_key_signature_type, generated_pub_key.type)
        self.assertEqual(public_key_controller, generated_pub_key.controller)
        self.assertEqual(second_public_key_alias, second_generated_pub_key.alias)
        self.assertEqual(second_public_key_signature_type, second_generated_pub_key.type)
        self.assertEqual(second_public_key_controller, second_generated_pub_key.controller)

    def test_invalid_alias_throws_exception(self):
        new_did = DID()
        public_key_alias = 'myPublicKey'
        public_key_signature_type = SignatureType.RSA.value
        self.assertRaises(ValueError, lambda: new_did.add_public_key(public_key_alias, public_key_signature_type))

    def test_used_alias_throws_exception(self):
        new_did = DID()
        new_did.add_public_key()
        self.assertRaises(ValueError, lambda: new_did.add_public_key())

    def test_invalid_signature_type_throws_exception(self):
        new_did = DID()
        public_key_alias = 'mypublickey'
        public_key_signature_type = 'invalid_signature_type'
        self.assertRaises(ValueError, lambda: new_did.add_public_key(public_key_alias, public_key_signature_type))

    def test_invalid_controller_throws_exception(self):
        new_did = DID()
        public_key_alias = 'mypublickey'
        public_key_signature_type = SignatureType.RSA.value
        public_key_controller = 'did:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b8005'
        self.assertRaises(ValueError, lambda: new_did.add_public_key(public_key_alias, public_key_signature_type,
                                                                     public_key_controller))
        public_key_alias = 'mysecpublickey'
        public_key_controller = 'did:fctr:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b800'
        self.assertRaises(ValueError, lambda: new_did.add_public_key(public_key_alias, public_key_signature_type,
                                                                     public_key_controller))


class Encryptor(unittest.TestCase):
    def test_encrypt_decrypt(self):
        new_did = DID()
        new_did.add_public_key()
        generated_public_key = new_did.public_keys[0]

        password = '123456'
        encrypted_keys = new_did.export_encrypted_keys(password)
        decrypted_keys = decrypt_keys(encrypted_keys, password)
        decrypted_public_key = decrypted_keys[0]

        self.assertEqual(generated_public_key.alias, decrypted_public_key['alias'])
        self.assertEqual(generated_public_key.type, decrypted_public_key['type'])
        self.assertEqual(str(generated_public_key.private_key, 'utf8'), decrypted_public_key['privateKey'])

    def test_decrypt_keys_from_ui_store(self):
        pw = '123qweASD!@#'
        salt = 'cChkzEf0dWzlnp1UqYOtJLbljr+yp7hsyEngrQXqF3g='
        vector = 'iktNUmPe/P2JaZbJJR0Mww=='
        ctx = '5od26bPl/Z+BxwCX9i5WSlGYymy2ltUmW5F6sV5K4DsGo05anopJCwj7m7RHCMCJcoUlFy8PBgkow5lZNnpJRPPC6bjn0euW3kVLtLecgWy/ryOQx3tOV8CuY6iITV8Akk9KBBqQHIja4ePaUWKRlZM1YL9tFbFivNAbEt1ueWHhNb6zln7zwnAWJbXTK4Tn4piFrADXksoQYdt6lfPJbCWFhyRSCtY/WJLKORaeQ8qywN4CTKBb92Ae2xT4upZBWXlEURutk45I8AXMIEKpIpZXSczhVb06qGruIV/z5dQQX8ngExjDo7HsDcgtew+wDbBc4JQAtT/duQfWvVGe8QQPiu06U6F5V8u209WXSNHj02Hm8Jqck6upqPlBNJAhWw+K9A=='
        expected_keys = [
            {
                'alias': 'myfirstkey',
                'type': 'Ed25519',
                'privateKey': '3q1GGcMzEBXco2GiJKaH1bRzBuGcRWA5a2zgRPSgNzRcFWBfBzCh3Hi4kivHBTJ7NPmDtdskzQ1AL5f9vQKoMZ12'
            },
            {
                'alias': 'myseckey',
                'type': 'ECDSASecp256k1',
                'privateKey': 'CJiZnpMLpAsdB5nu4FJUaiWKGs5PyCwuNNnHFAfuZFeJ'
            }]

        decrypted_keys = decrypt_keys_from_ui_store(ctx, pw, salt, vector)
        self.assertEqual(expected_keys, decrypted_keys)


if __name__ == '__main__':
    unittest.main()
