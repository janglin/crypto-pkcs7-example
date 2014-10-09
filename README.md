crypto-pkcs7-example
====================

An example taken from the site below for posteriety (requires pycrypto)
and getting up to speed quickly

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

There isn't an offical release per se, but to use it with pip add the following to your requirements.txt file:
-e git+https://github.com/owenfi/crypto-pkcs7-example.git#egg=pkcs

or
-e git+https://github.com/owenfi/crypto-pkcs7-example.git@15180eeacab6fbc5772cf7fd6687dd712e5d763b#egg=pkcs-master
to get a specific release

Example of sharing encrypted information between Python and the .NET Framework. It contains a Python implementation of RFC 2315 PKCS#7 encoding. It also contains a Python implementation of RFC 2437 PKCS1-v1_5 encoding and PKCS1-v2.0 (OAEP) encoding. In this example, the data is encrypted in Python and decrypted using the .NET Framework and the C# language.

This code was originally used as part of this blog post.
http://japrogbits.blogspot.com/2011/02/using-encrypted-data-between-python-and.html

The PyCrypto library is available at:
https://github.com/dlitz/pycrypto
with documentation here:
https://www.dlitz.net/software/pycrypto/

