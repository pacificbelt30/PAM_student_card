import os
import hashlib
import binascii
def get_salt(nbyte: int = 32) -> bytes:
    return os.urandom(nbyte)

def get_hash_with_salt(idm: bytes,salt: bytes) -> bytes:
    return bytes(hashlib.sha256(salt + idm).hexdigest(), encoding='utf-8')

if __name__ == "__main__":
    salt = get_salt()
    print('salt      :', binascii.hexlify(salt))
    print('hashed idm:', get_hash_with_salt(bytes('test', encoding='utf-8'), salt))
