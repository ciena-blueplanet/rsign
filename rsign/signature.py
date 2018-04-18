# Copyright(c) 2014, Cyan, Inc. All rights reserved.
import hmac
import hashlib
import binascii


def _clean(string_or_bytes):
    """ String to Byte conversion """
    if isinstance(string_or_bytes, (bytes, bytearray)):
        return string_or_bytes

    return string_or_bytes.encode('utf-8')


if not hasattr(hmac, 'compare_digest'):
    # Backport compare_digest to python 2.X
    # see http://bugs.python.org/review/15061/diff2/5181:5214/Lib/hmac.py
    # and http://bugs.python.org/issue15061
    def compare_digest(a, b):
        """Returns the equivalent of 'a == b', but avoids content based short
        circuiting to reduce the vulnerability to timing attacks."""
        # Consistent timing matters more here than data type flexibility
        if not (isinstance(a, bytes) and isinstance(b, bytes)):
            raise TypeError("inputs must be bytes instances")

        # We assume the length of the expected digest is public knowledge,
        # thus this early return isn't leaking anything an attacker wouldn't
        # already know
        if len(a) != len(b):
            return False

        # We assume that integers in the bytes range are all cached,
        # thus timing shouldn't vary much due to integer object creation
        result = 0
        for x, y in zip(a, b):
            result |= ord(x) ^ ord(y)
        return result == 0
    hmac.compare_digest = compare_digest


class Signature(object):
    """ Abstract class representing a cryptographic signature """

    def sign_string(self, key, text):
        """ Return the signing method's digest """
        raise NotImplementedError()

    def compare(self, s1, s2):
        """
        verify s1 == s2.  this _must_ be a function
        that provides constant time verification
        """
        raise NotImplementedError()

    def verify_signature(self, key, text, signature):
        """ Verify that the signature matches the received digest """
        actual = self.sign_string(key, text)
        return self.compare(signature, actual)


class HMACSignature(Signature):
    """ Sign and verify a string using HMAC """

    def __init__(self, hash_function=hashlib.sha256):
        self.hash_fn = hash_function

    def compare(self, s1, s2):
        return hmac.compare_digest(s1, s2)

    def sign_string(self, key, text):
        """ Return the signing method's digest """
        key, text = _clean(key), _clean(text)
        return hmac.new(key, text, self.hash_fn).digest()


class Base64Mixin(Signature):
    """ Encode a Signature using Base64 """

    def verify_signature(self, key, text, signature):
        """ Verify that the signature matches the received digest """
        binary = binascii.a2b_base64(signature)
        # Can't call our own sign_string because it's base64 too!
        actual = super(Base64Mixin, self).sign_string(key, text)
        return self.compare(binary, actual)

    def sign_string(self, key, text):
        """ Return the signing method's digest """
        binary = super(Base64Mixin, self).sign_string(key, text)
        return binascii.b2a_base64(binary).replace('\n', '')


class HMACBase64Signature(Base64Mixin, HMACSignature):
    """ HMAC Signed and Base64 encoded Signature """
    pass
