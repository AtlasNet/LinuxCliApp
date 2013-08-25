import json
import os
import tempfile
import time
import calendar
from M2Crypto import RSA, EVP
from datetime import datetime

from atlasclient.nodeclient import NodeClient


__all__ = ['AtlasMessage', 'AtlasClient', 'AtlasContact']


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
        return (os.urandom(32), os.urandom(16))

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
        self.timestamp = None

    def dump(self):
        return {
            'type': self.type,
            'blob': self.blob.encode('base64'),
            'signature': self.signature.encode('base64') if self.signature else None,
            'timestamp': self.timestamp,
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

    def verify_signature(self, data, signature):
        digest = EVP.MessageDigest('sha1')
        digest.update(data)
        try:
            #return self.public_key.verify(digest.digest(), signature, algo='sha512') == 1
            return self.public_key.verify_rsassa_pss(digest.digest(), signature) == 1
        except:
            return False


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

    def __decrypt(self, data):
        return self.__get_private_key().private_decrypt(data, RSA.pkcs1_oaep_padding)

    def has_key(self):
        return self.config['private_key'] != None
    
    def regenerate_key(self):
        key = RSA.gen_key(self.key_length, 65537, lambda: None)
        self.config['private_key'] = _get_output(lambda x: key.save_key(x, None))
        self.config['public_key'] = _get_output(lambda x: key.save_pub_key(x))

    def authenticate(self, nc):
        challenge = nc.client.getAuthChallenge(self.config['public_key']).decode('base64')
        response = self.__decrypt(challenge)
        return nc.client.confirmAuth(response.encode('base64'))

    def prepare_message(self, message, recipient, sign=True):
        if sign:
            key = self.__get_private_key()
            digest = EVP.MessageDigest('sha1')
            digest.update(message.blob)
            signature = key.sign_rsassa_pss(digest.digest())
            #signature = key.sign(digest.digest(), algo='sha512')
            message.signature = signature
        
        message.timestamp = int(calendar.timegm(datetime.utcnow().utctimetuple()))
        data = json.dumps(message.dump())
        
        key, iv = AES.generate_key()
        aes = AES(key, iv)
        
        data = aes.encrypt(data)

        package = {
            'data': data.encode('base64'),
            'key': recipient.public_key.public_encrypt(key, RSA.pkcs1_oaep_padding).encode('base64'),
            'iv': recipient.public_key.public_encrypt(iv, RSA.pkcs1_oaep_padding).encode('base64'),
            'recipient_key': recipient.save()['public_key']
        }

        return json.dumps(package)

    def post_message(self, message, recipient, client, sign=True):
        client.postMessage(self.prepare_message(message, recipient, sign=sign), recipient.save()['public_key'])

    def retrieve(self, listing):
        nc = NodeClient(listing.node.host, listing.node.port)
        nc.connect()
        self.authenticate(nc)

        if not nc.client.hasMessage(listing.id):
            nc.disconnect()
            return None

        msg = nc.client.retrieveMessage(listing.id)
        nc.disconnect()
        data = json.loads(msg.data)

        aes = AES(
            self.__decrypt(data['key'].decode('base64')),
            self.__decrypt(data['iv'].decode('base64'))
        )

        data = json.loads(aes.decrypt(data['data'].decode('base64')))

        blob = data['blob'].decode('base64')
        signed_by = None
        if data['signature']:
            signature = data['signature'].decode('base64')
            if signature:
                for contact in self.contacts:
                    if contact.verify_signature(blob, signature):
                        signed_by = contact

        return {
            'type': data['type'],
            'blob': blob,
            'signed_by': signed_by,
            'signed': data['signature'] is not None,
            'date': datetime.fromtimestamp(data.get('timestamp', 0)),
        }

    def save(self):
        self.config['contacts'] = []
        for contact in self.contacts:
            self.config['contacts'].append(contact.save())
        open(self.__data_path('config.json'), 'w').write(json.dumps(self.config, indent=4))
