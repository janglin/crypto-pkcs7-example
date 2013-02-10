import binascii
import cStringIO
import hashlib
import os
import struct

class PKCS1Error(RuntimeError):
    '''
    Base class for PKCS1 encoding/decoding errors.
    Error of this or derived classes should be caught
    by the calling code and then a generic error message
    should be returned to the caller.
    '''
    pass

class DecoderError(PKCS1Error):
    '''
    Raised when a decoding error has been detected.
    '''
    pass

class EncoderError(PKCS1Error):
    '''
    Raise when an encoding error has been detected.
    '''
    pass


class PKCSAuxiliary(object):
    '''
    Auxiliary functions used in RFC 2437
    '''

    def __init__(self):
        self._hash_length = None

    @property
    def hash_length(self):
        if not self._hash_length:
            hasher = self.create_hasher()
            self._hash_length = hasher.digest_size

        return self._hash_length

    @staticmethod
    def create_hasher():
        return hashlib.sha1()

    @staticmethod
    def compute_hash(data, hex_digest=False):
        hasher = PKCSAuxiliary.create_hasher()
        hasher.update(data)
        if hex_digest:
            return hasher.hex_digest()
        else:
            return hasher.digest()

    def mgf(self, seed, length):
        '''
        RFC 2437 page 28 MFG1
        '''
        counter = 0
        output = cStringIO.StringIO()
        try:
            limit = length / self.hash_length
            while counter <= limit:
                C = self.i2osp(counter)
                output.write(self.compute_hash(seed + C))
                counter += 1

            raw_mask = output.getvalue()
            if len(raw_mask) < length:
                raise PKCS1Error("MGF: mask too long")
        finally:
            output.close()

        mask = raw_mask[:length]
        return mask

    def i2osp(self, x):
        '''
        RFC 2437 page 6 I2OSP
        Special case where length = 4
        '''
        if x > 256 ** 4:
            raise PKCS1Error("I2OSP: integer too large")

        sp = (
            int((x >> 24) & 0xff),
            int((x >> 16) & 0xff),
            int((x >> 8) & 0xff),
            int((x >> 0) & 0xff)
        )

        return struct.pack('BBBB', *sp)

    @staticmethod
    def xor(a, b):
        '''
        RFC 2437  bitwise exclusive-or of two octet strings.
        page 23
        '''
        if len(a) != len(b):
            raise PKCS1Error("XOR: invalid input lengths")

        output = cStringIO.StringIO()

        try:
            for i in xrange(len(a)):
                x = int(binascii.hexlify(a[i]), 16)
                y = int(binascii.hexlify(b[i]), 16)
                output.write('%02x' % (x ^ y))

            data = output.getvalue()

        finally:
            output.close()

        return binascii.unhexlify(data)


class OAEPEncoder(PKCSAuxiliary):
    '''
    RFC 2437 9.1.1 EME-OAEP PKCS1-v2.0
    9.1.1.1 EME-OAEP-ENCODE
    9.1.1.2 EME-OAEP-DECODE
    '''

    def __init__(self):
        super(OAEPEncoder, self).__init__()


    def encode(self, msg, salt='', keybits=1024):
        k = keybits / 8
        if len(msg) > (k - 2 - 2 * self.hash_length):
            raise EncoderError("EME-OAEP: message too long")

        emLen = k - 1
        if (emLen < (2 * self.hash_length + 1) or
            len(msg) > (emLen - 1 - 2 * self.hash_length)):
            raise EncoderError("EME-OAEP: message too long")

        pslen = emLen - len(msg) - 2 * self.hash_length - 1
        output = cStringIO.StringIO()
        try:
            for _ in xrange(pslen):
                output.write('%02x' % 0)
            ps = binascii.unhexlify(output.getvalue())
            assert len(ps) == pslen, "PS: invalid length"
        finally:
            output.close()

        shash = self.compute_hash(salt)
        dbout = cStringIO.StringIO()
        try:
            dbout.write(shash)
            dbout.write(ps)
            dbout.write('\x01')
            dbout.write(msg)
            db = dbout.getvalue()
        finally:
            dbout.close()

        seed = os.urandom(self.hash_length)
        assert len(seed) == self.hash_length

        dbMask = self.mgf(seed, emLen - self.hash_length)
        maskedDB = self.xor(db, dbMask)
        seedMask = self.mgf(maskedDB, self.hash_length)
        maskedSeed = self.xor(seed, seedMask)
        emout = cStringIO.StringIO()
        try:
            emout.write(maskedSeed)
            emout.write(maskedDB)
            emsg = emout.getvalue()
        finally:
            emout.close()
        return emsg


    def decode(self, emsg, salt=''):
        if len(emsg) < (2 * self.hash_length + 1):
            raise DecoderError("EME-OAEP: decoding error")

        maskedSeed = emsg[:self.hash_length]
        maskedDB = emsg[self.hash_length:]
        seedMask = self.mgf(maskedDB, self.hash_length)
        seed = self.xor(maskedSeed, seedMask)
        dbMask = self.mgf(seed, len(emsg) - self.hash_length)
        db = self.xor(maskedDB, dbMask)
        shash = self.compute_hash(salt)

        db_shash = db[:self.hash_length]
        if db_shash != shash:
            raise DecoderError("EME-OAEP: decoding error")

        index = db.find('\x01', self.hash_length)
        if - 1 == index:
            raise DecoderError("EME-OAEP: decoding error")

        return db[index + 1:]



class PKCS1v1_5Encoder(object):
    '''
    RFC 2437 9.1.2 EME-PKCS1-v1_5
    
    9.1.2.1 EME-PKCS1-v1_5-ENCODE
    9.1.2.2 EME-PKCS1-v1_5-DECODE
    '''

    def encode(self, msg, keybits=1024):
        emLen = keybits / 8 - 1
        if len(msg) > (emLen - 10):
            raise EncoderError("PKCS1-V1.5: message too long")

        ps = self.rnd_non_zero(emLen - len(msg) - 2)
        assert len(ps) >= 8, "PKCS1-V1.5: invalid PS"

        emout = cStringIO.StringIO()
        try:
            emout.write('\x02')
            emout.write(ps)
            emout.write('\x00')
            emout.write(msg)
            emsg = emout.getvalue()
        finally:
            emout.close()

        return emsg


    def decode(self, emsg):
        if len(emsg) < 10:
            raise DecoderError("PKCS1-V1.5: decoding error")

        if '\x02' != emsg[0]:
            raise DecoderError("PKCS1-V1.5: decoding error")

        index = emsg.find('\x00')
        if - 1 == index:
            raise DecoderError("PKCS1-V1.5: decoding error")

        ps = emsg[1:index]
        if len(ps) < 8:
            raise DecoderError("PKCS1-V1.5: decoding error")

        return emsg[index + 1:]


    @staticmethod
    def rnd_non_zero(length):
        rnd = os.urandom(length)
        while - 1 != rnd.find('\x00'):
            rnd = rnd.replace('\x00', os.urandom(1))
        return rnd

