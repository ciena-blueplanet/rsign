# -*- coding: utf-8 -*-
"""
Copyright(c) 2014, Cyan, Inc. All rights reserved.
"""

import os
import time
import unittest
from binascii import hexlify
from rsign import SignedRequest, get_auth_header_values
from rsign.signature import _clean


class TestRequest(unittest.TestCase):
    """ Verify request objects behave as expected """

    def setUp(self):
        ''' Validate the Authurization header has the correct format '''
        method = "POST"
        host = "example.com"
        path = "/path/to/resource"
        port = "8080"
        self.request = SignedRequest(method, host, path, port)
        # This doesn't have to be decoded on the other side.  It just has to be ascii printable
        self.nonce = hexlify(os.urandom(32))
        self.timestamp = str(int(time.time()))
        # This doesn't have to be decoded on the other side.  It just has to be ascii printable
        self.key_id = hexlify(os.urandom(32))
        self.key = hexlify(os.urandom(40))

    def test_request_valid(self):
        ''' Validate the request header validates correctly '''
        auth_header = self.request.get_signed_header(self.nonce, self.timestamp, self.key_id, self.key)
        self.assertTrue(self.request.verify_signed_header(auth_header[1], self.key),
                        "Verify a signed request header authenticates properly.")
        self.assertFalse(self.request.verify_signed_header(auth_header[1], self.key[:-1]),
                         "Verify a tampered with key or request doesn't verify properly")
        self.request.method = "GET"
        self.assertFalse(self.request.verify_signed_header(auth_header[1], self.key),
                         "Verify a tampered with key or request doesn't verify properly")
        self.request.method, self.request.path = "POST", "/not/path"
        self.assertFalse(self.request.verify_signed_header(auth_header[1], self.key),
                         "Verify a tampered with key or request doesn't verify properly")

    def test_request_unicode(self):
        ''' Validate the request validates with unicode correctly '''
        self.key = u'¬˚∆œ∑¬˚œ∑´¬œ∑´∆˚∆ç∂√å∫∂√˚´∑ˆø'
        auth_header = self.request.get_signed_header(self.nonce, self.timestamp, self.key_id, self.key)
        self.assertTrue(self.request.verify_signed_header(auth_header[1], self.key))

    def test_get_auth_header_values(self):
        ''' Validate the Auth Header properly parses into dictionary '''
        header = 'MAC id="123", ts="123", nonce="nonce", mac="2tduYjW+ZTdQyN/aOQxk3fVBnaaNs5qMmnDVIfvp16g="'
        expect = dict(id="123", ts="123", nonce="nonce", mac="2tduYjW+ZTdQyN/aOQxk3fVBnaaNs5qMmnDVIfvp16g=")
        actual = get_auth_header_values(header)
        self.assertEqual(expect, actual, 'Assert header values are equivalent')


class TestClean(unittest.TestCase):

    def test_clean_should_convert_unicode_to_bytes(self):
        self.assertEqual(_clean(u'Hello'), b'Hello')

    def test_clean_should_convert_string_to_bytes(self):
        self.assertEqual(_clean('Hello'), b'Hello')

    def test_clean_should_leave_bytes_as_is(self):
        self.assertEqual(_clean(b'Hello'), b'Hello')


if __name__ == '__main__':
    unittest.main()
