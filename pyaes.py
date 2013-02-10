from Crypto.Cipher import AES
from pkcs7 import PKCS7Encoder
import base64

key = 'your key 16bytes'
# 16 byte initialization vector
iv = '1234567812345678'

aes = AES.new(key, AES.MODE_CBC, iv)
encoder = PKCS7Encoder()

text = 'This is my plain text'

# pad the plain text according to PKCS7
pad_text = encoder.encode(text)
# encrypt the padding text
cipher = aes.encrypt(pad_text)
# base64 encode the cipher text for transport
enc_cipher = base64.b64encode(cipher)

print enc_cipher

