
from Crypto.PublicKey import RSA
from pkcs1 import OAEPEncoder
import base64
import binascii
import os
import pickle

class RSAKey(object):

    def __init__(self, keybitsize, encoder=OAEPEncoder()):
        self._encoder = encoder
        self._keysize = keybitsize
        self._key = RSA.generate(keybitsize, os.urandom)

    @property
    def key(self):
        return self._key

    @property
    def key_size(self):
        return self._keysize

    ## Get the public RSA key used to encrypt data as
    #  an XML string.
    #  @param xml_format True if the key should be returned as XML.
    #  If False, the key is returned as a base64 encoded pickled 
    #  Python object.
    #  @return: An XML string representation of the 
    #           public RSA key. Each node is a base64
    #           encoded string. It has the following 
    #           structure.
    #           \<RSAKeyValue\>
    #               \<Exponent\>AQAB\</Exponent\>
    #               \<Modulus\>some data\</Modulus\>
    #           \</RSAKeyValue\> 
    def public_key(self, xml_format):
        pkey = self._key.publickey()

        if xml_format:
            # Pads with leading zeros if needed.
            def ensure_length(hexstr):
                if len(hexstr) % 2 != 0:
                    return '0' + hexstr
                else:
                    return hexstr
            # make an encoded child node
            def add_child(tag, n):
                str_n = ensure_length('%x' % n)
                n_bytes = binascii.unhexlify(str_n)

                sub = et.SubElement(root, tag)
                sub.text = base64.b64encode(n_bytes)

            root = et.Element('RSAKeyValue')
            add_child('Exponent', pkey.e)
            add_child('Modulus', pkey.n)
            return tostring(root)
        else:
            return base64.b64encode(pickle.dumps(pkey))

    ## Encrypt data with the public RSA key.
    #  @param data The data to be encrypted
    #  @return A base64 encoded string that is the encrypted data.
    def encrypt(self, data):
        enc_data = self._encoder.encode(data, keybits=self._keysize)
        cipher = self._key.encrypt(enc_data, '')
        return base64.b64encode(cipher[0])

    ## Decrypt data with the private RSA key.
    #  @param encoded_cipher A base64 encoded string of encrypted data.
    #  @return The decrypted data as a string.
    def decrypt(self, encoded_cipher):
        cipher = base64.b64decode(encoded_cipher)
        enc_data = self._key.decrypt(cipher)
        data = self._encoder.decode(enc_data)
        return data
