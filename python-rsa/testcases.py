import unittest
import pathlib
from tools import decrypt, encrypt, generateKeys
from settings import MY_ENCRYPTED_PASSWORD

class RSATestCases(unittest.TestCase):
    def _test_generate_keys(self):
        generateKeys()
        self.assertTrue(pathlib.Path('keys/publicKey.pem').exists())
        self.assertTrue(pathlib.Path('keys/privateKey.pem').exists())

    def test_encrypt_password(self):
        password = 'paste your password here!'
        encryptedPassword = encrypt(password)
        self.assertNotEuqal(password, encryptedPassword)
        print('copy your encrypted password from below:')
        print(encryptedPassword)
    
    def test_decrypt_password(self):
        self.assertTrue(MY_ENCRYPTED_PASSWORD is not None and len(MY_ENCRYPTED_PASSWORD) > 0)
        decryptedPassword = decrypt(MY_ENCRYPTED_PASSWORD)
        self.assertEqual('', decryptedPassword)

if __name__ == '__main__':
    unittest.main()
