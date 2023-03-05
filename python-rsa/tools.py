import re
import rsa

# reference:
# [Implementing RSA Encryption and Decryption in Python](https://www.section.io/engineering-education/rsa-encryption-and-decryption-in-python/)

def generateKeys():
    """
    generate public key and private key.
    call this function only if update certificate file (.pem) required
    """
    (publicKey, privateKey) = rsa.newkeys(1024)
    with open('keys/publicKey.pem','wb') as p:
        p.write(publicKey.save_pkcs1('PEM'))
    with open('keys/privateKey.pem', 'wb') as p:
        p.write(privateKey.save_pkcs1('PEM'))

__PUBLIC_KEY = None
'''public key for encrypt message'''

__PRIVATE_KEY = None
'''private key for decrypt message'''

def _loadKeys():
    """load public key and private key"""
    global __PUBLIC_KEY, __PRIVATE_KEY
    if __PUBLIC_KEY is None or __PRIVATE_KEY is None:
        with open('keys/publicKey.pem','rb') as p:
            __PUBLIC_KEY = rsa.PublicKey.load_pkcs1(p.read())
        with open('keys/privateKey.pem', 'wb') as p:
            __PRIVATE_KEY = rsa.PrivateKey.load_pkcs1(p.read())
    return __PUBLIC_KEY, __PRIVATE_KEY

def _fixEscapeCharactersIssue(rawstr: str):
    hexDecMapping = {
        '0': 0,
        '1': 1,
        '2': 2,
        '3': 3,
        '4': 4,
        '5': 5,
        '6': 6,
        '7': 7,
        '8': 8,
        '9': 9,
        'a': 10,
        'b': 11,
        'c': 12,
        'd': 13,
        'e': 14,
        'f': 15
    }
    def __hex2chr(fourchrs: str):
        """
        replace hex (e.g.: \\x0f) with single control character (e.g.: \x0f).
        size: 4 -> 1
        """
        hexPosition = fourchrs[2:]
        decPosition = (hexDecMapping[hexPosition[0]]*16)+hexDecMapping[hexPosition[1]]
        return chr(decPosition)
    matchResult = re.search(r'\\x([0-f]{2})', rawstr)
    while matchResult is not None and matchResult.group() is not None:
        fourchrs = matchResult.group()
        right1char = __hex2chr(fourchrs)
        rawstr = rawstr.replace(fourchrs, right1char)
        matchResult = re.search(r'\\x([0-f]{2})', rawstr)
    # special case: replace \' with ' (caused by manual copy value from IDE)
    # special case: replace \" with " (caused by manual copy value from IDE)
    rawstr = rawstr.replace(r"\'", "'").replace(r'\"','"')
    return rawstr

def encrypt(message:str)->str:
    if message is None or type(message) != str or len(message) == 0:
        raise ValueError(message)
    publicKey, _ = _loadKeys()
    encryptedMessage = rsa.encrypt(message.encode('latin-1'), publicKey)
    return encryptedMessage.decode('latin-1')

def decrypt(cipertext: str) -> str:
    try:
        # step 1: fix escape character issue in .env file
        cipertext = _fixEscapeCharactersIssue(cipertext)
        # step 2: decrypt via rsa
        _, privateKey = _loadKeys()
        return rsa.decrypt(cipertext.encode('latin-1'), privateKey).decode('latin-1')
    except:
        raise rsa.DecryptionError()
