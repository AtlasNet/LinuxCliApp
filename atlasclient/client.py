import binascii
import json
import os
import tempfile
from base64 import b64encode, b64decode
from M2Crypto import RSA, EVP


def _get_output(fx):
    f = tempfile.NamedTemporaryFile(delete=False)
    f.close()
    fx(f.name)
    content = open(f.name).read()
    os.unlink(f.name)
    return content

def _provide_input(fx, data):
    f = tempfile.NamedTemporaryFile(delete=False)
    f.write(data)
    f.close()
    result = fx(f.name)
    os.unlink(f.name)
    return result
    

class AES (object):
    """ AES-256-CBC """

    @staticmethod
    def generate_key():
        return (os.urandom(256 / 8), os.urandom(256 / 8))

    def __init__(self, key, iv):
        self.key = key
        self.iv = iv

    def encrypt(self, data):
        encipher = EVP.Cipher(alg='aes_256_cbc', key=self.key, iv=self.iv, op=1)
        result = encipher.update(data)
        result += encipher.final()
        return result

    def decrypt(self, data):
        decipher = EVP.Cipher(alg='aes_256_cbc', key=self.key, iv=self.iv, op=0)
        result = decipher.update(data)
        result += decipher.final()
        return result


class AtlasMessage (object):
    def __init__(self):
        self.type = 'text'
        self.blob = ''
        self.signature = None

    def dump(self):
        return {
            'type': self.type,
            'blob': b64encode(self.blob),
            'signature': self.signature,
        }


class AtlasContact (object):
    def __init__(self):
        self.name = None
        self.public_key = None

    def load(self, json):
        self.name = json['name']
        self.public_key = _provide_input(lambda x: RSA.load_pub_key(x), json['public_key'])

    def save(self):
        return {
            'name': self.name,
            'public_key': _get_output(lambda x: self.public_key.save_pub_key(x))
        }


class AtlasClient (object):
    def __init__(self, data_dir):
        self.data_dir = data_dir
        if not os.path.exists(data_dir):
            os.mkdirs(data_dir)
        self.key_length = 1024
        if os.path.exists(self.__data_path('config.json')):
            self.config = json.load(open(self.__data_path('config.json')))
        else:
            self.config = {}
        self.config.setdefault('public_key', None)
        self.config.setdefault('private_key', None)
        self.config.setdefault('contacts', [])
        self.contacts = []
        for c in self.config['contacts']:
            contact = AtlasContact()
            contact.load(c)
            self.contacts.append(contact)

    def __data_path(self, path):
        return os.path.join(self.data_dir, path)

    def __get_private_key(self):
        return _provide_input(RSA.load_key, self.config['private_key'])

    def regenerate_key(self):
        key = RSA.gen_key(self.key_length, 65537, lambda: None)
        self.config['private_key'] = _get_output(lambda x: key.save_key(x, None))
        self.config['public_key'] = _get_output(lambda x: key.save_pub_key(x))

    def prepare_message(self, message, recipient, sign=True):
        if sign:
            key = self.__get_private_key()
            digest = EVP.MessageDigest('sha1')
            digest.update(message.blob)
            signature = key.sign_rsassa_pss(digest.digest())
            message.signature = signature.encode('base64')
        data = json.dumps(message.dump())
        
        key, iv = AES.generate_key()
        aes = AES(key, iv)
        
        data = aes.encrypt(data)

        package = {
            'data': b64encode(data),
            'key': recipient.public_key.public_encrypt(key, RSA.pkcs1_oaep_padding).encode('base64'),
            'iv': recipient.public_key.public_encrypt(iv, RSA.pkcs1_oaep_padding).encode('base64'),
            'recipient_key': recipient.save()['public_key']
        }

        return json.dumps(package)

    def save(self):
        self.config['contacts'] = []
        for contact in self.contacts:
            self.config['contacts'].append(contact.save())
        open(self.__data_path('config.json'), 'w').write(json.dumps(self.config, indent=4))
