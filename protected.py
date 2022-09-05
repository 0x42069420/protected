"""

MIT License

Copyright (c) 2022 0x42069420

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

"""

from typing import Any, Tuple, BinaryIO

from cryptography.fernet import Fernet
from pickle import dumps as pickle_dumps, loads as pickle_loads
from hmac import new as new_hmac
from hashlib import sha1

class IntegrityCheckFailed (Exception): pass

def generate_fernet_key() -> bytes:
    """ generate a new fernet key, using cryptography.fernet.

        return:
            fernet_key (bytes): new fernet key

        >>> fernet_key = protected.generate_fernet_key()
    """
    return Fernet.generate_key()

def encrypt(fernet_key:bytes, obj:Any) -> Tuple[str, bytes]: 
    """ dumps object into a pickle str, then encrypts it using the supplied fernet key.

        args:
            fernet_key (bytes): fernet key to be used for encryption
            obj (any): object to be encrypted

        return:
            digital_signature (str): cryptographic hash of the encrypted object
            encrypted (bytes): encrypted object

        >>> digital_signature, encrypted = protected.encrypt(fernet_key, obj)
    """
    encrypted = Fernet(fernet_key).encrypt(pickle_dumps(obj))
    digital_signature = new_hmac(fernet_key, encrypted, sha1).hexdigest()
    return digital_signature, encrypted

def decrypt(fernet_key:bytes, digital_signature:str, encrypted:bytes) -> Any: 
    """ decrypts the encrypted object using the supplied fernet key and loads it.

        args:
            fernet_key (bytes): fernet key that was used for encryption
            digital_signature (str): expected cryptographic hash of the encrypted object
            encrypted (any): object to be decrypted

        return:
            obj (any): decypted object

        raise:
            IntegrityCheckFailed: the expected digital signature does not match the one generated from the encrypted object

        >>> obj = protected.decrypt(fernet_key, digital_signature, encrypted)
    """
    new_digital_signature = new_hmac(fernet_key, encrypted, sha1).hexdigest()
    if new_digital_signature != digital_signature: raise IntegrityCheckFailed()
    return pickle_loads(Fernet(fernet_key).decrypt(encrypted))

def dump(fernet_key:bytes, obj:Any, file:BinaryIO) -> str:
    """ encrypt object and write it to binary io.

        args:
            fernet_key (bytes): fernet key to be used for encryption
            obj (any): object to be encrypted
            file (binary_io): io to write encrypted object to

        return:
            digital_signature (str): cryptographic hash of the encrypted object
            
        >>> with open("example.pkl", "wb") as file: 
        >>>     digital_signature = protected.dump(fernet_key, obj, file)
    """
    digital_signature, data = encrypt(fernet_key, obj)
    file.write(data)
    return digital_signature

def load(fernet_key:bytes, digital_signature:str, file:BinaryIO) -> Any:
    """ read encrypted object from binary io and load it.

        args:
            fernet_key (bytes): fernet key that was used for encryption
            digital_signature (str): expected cryptographic hash of the encrypted object
            file (binary_io): io to read encrypted object from

        return:
            obj (any): decypted object

        raise:
            IntegrityCheckFailed: the expected digital signature does not match the one generated from the encrypted object
            
        >>> with open("example.pkl", "rb") as file: 
        >>>     obj = protected.load(fernet_key, digital_signature, file)
    """
    return decrypt(fernet_key, digital_signature, file.read())