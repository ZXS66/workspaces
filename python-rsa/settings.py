import os
from dotnet import load_dotenv
from tools import encrypt, decrypt

load_dotenv()

MY_ENCRYPTED_PASSWORD = decrypt(os.getenv('MY_ENCRYPTED_PASSWORD'))
'''decrypted password from .env file'''
