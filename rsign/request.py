# Copyright(c) 2014, Cyan, Inc. All rights reserved.
import re
try:
    # pylint: disable=W0611
    from typing import Union, Tuple  # noqa
    DEFINITELY_TYPED = True
except ImportError:
    DEFINITELY_TYPED = False

from rsign.signature import HMACBase64Signature


if DEFINITELY_TYPED:
    Text = Union[bytes, bytearray, str]  # pylint: disable=C0103


def to_bytes(bytes_or_string):
    if isinstance(bytes_or_string, (bytes, bytearray)):
        return bytes_or_string
    return bytes_or_string.encode('utf-8')


def to_string(bytes_or_string):
    if isinstance(bytes_or_string, (bytes, bytearray)):
        return bytes_or_string.decode('utf-8')
    return bytes_or_string


def get_auth_header_values(header_string):
    """ Returns a dict mapping the header keys to their values """
    # Get the header key and value (value matches any non-quote contained in quotes)
    reg = re.compile(r'(\w+)="([^"]+)"')
    return dict(reg.findall(header_string))


def normalize(timestamp, nonce, method, path, host, port):  # pylint: disable=R0913
    # type: (Text, Text, Text, Text, Text, Text) -> bytes
    """ Accepts args as strings and returns the normalized form for signing """
    normalized = b'\n'.join([
        timestamp,
        nonce,
        method.upper(),
        path,
        host.lower(),
        port,
    ])
    return normalized


class SignedRequest(object):
    """ Signed request implementation """

    def __init__(self, method, host, path, port):
        self.method = to_bytes(method)
        self.host = to_bytes(host)
        self.path = to_bytes(path)
        self.port = to_bytes(port)

    def get_signed_header(self, nonce, timestamp, key_id, key):
        # type: (Text, Text, Text, Text) -> Tuple[str, str]
        """ Returns the Authorization header as a tuple """
        signature = self.sign_request(nonce, timestamp, key).decode()
        header = 'MAC id="{}", ts="{}", nonce="{}", mac="{}"'.format(
            to_string(key_id),
            to_string(timestamp),
            to_string(nonce),
            to_string(signature)
        )
        return ('Authorization', header)

    def verify_signed_header(self, header_string, key):
        """ Validates the request given the header string """
        h = get_auth_header_values(header_string)
        return self.verify_request(h['nonce'], h['ts'], key, h['mac'])

    def sign_request(self, nonce, timestamp, key):
        """ Returns the signature for the request's normalized string """
        normalized = normalize(
            to_bytes(timestamp),
            to_bytes(nonce),
            self.method,
            self.path,
            self.host,
            self.port,
            )
        signer = HMACBase64Signature()
        return signer.sign_string(to_bytes(key), normalized)

    def verify_request(self, nonce, timestamp, key, signature):
        """ Returns True if the signature matches the request, False otherwise """
        normalized = normalize(
            to_bytes(timestamp),
            to_bytes(nonce),
            self.method,
            self.path,
            self.host,
            self.port,
            )
        signer = HMACBase64Signature()
        return signer.verify_signature(to_bytes(key), normalized, to_bytes(signature))
