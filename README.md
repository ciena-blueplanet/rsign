RSign
-----

This repository contains code for signing API requests.

This code here is being implemented according to:

http://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-02

Although there are later drafts, they will not be implemented because they leave too much
room for flexibility.

Note that we are not implementing OAuth 2.0 proper, just the request signing mechanism for
our APIs.

Unfortunately, the draft does not cover handling request parameters in the body.  This was
in OAuth 1.0a but it requires delicate assembly of the string to be signed.  This is very
tedious to do especially when you add different forms of encoding that HTTP uses on top
of that.

Because of this, all APIs should be served over TLS in addition to what is laid out in
the draft.

Implementation Notes
--------------------

- We don't use the ext field for the normalized string
- We don't append the trailing newline character ('\n') to the normalized string
- The path _should_ include query parameters if they exist, but there's no enforcement (it's not enforceable)
- If necessary, the path and query parameters should be percent-encoded (per https://tools.ietf.org/html/rfc3986) prior to signing
- While the nonce representation isn't strictly defined, it is recommended to use standard or URL-safe Base64 Encoding per [RFC 4648](https://tools.ietf.org/html/rfc4648#page-7).

Installation
------------

- `pip install https://github.com/cyaninc/rsign/archive/master.zip`

Usage
-----

```python

from rsign import SignedRequest
from models import User
import binascii

sr = SignedRequest('GET', 'www.example.com', '/a/b/c?d=1&e=2&f=3', '443')
user = User.objects.get(id=1)
key_id = user.key_id
key = user.key
nonce = binascii.b2a_base64(os.urandom(32)).replace('\n', '')
timestamp = str(int(time.time()))
header, value = sr.get_signed_header(nonce, timestamp, key_id, key)
assert(sr.verify_signed_header(value, key))

```

Examples with and without the Rsign Library
-------------------------------------------

Values used for this example:

Inputs:
-------

HTTP Method = "GET"

URL = "http://bp.example.com:443/test/api/v1/foos?q=bar"

keyId = "ae71d7d92d7d4c659a7d3336db6c4c99"

keySecret = "7888cef675c44e8f862bae75186140d7"

Example Computed Values:
------------------------

timestamp = 1400863370

nonce = "Jw1ctgzz2X2n+6DDOBlEig=="

Output:
-------

mac = "oYhbGKDhOZZ9ReHQyZS0jMLwOSQDGplmWbtY3d+dORM="


### With RSign

```
>>> import rsign

>>> import requests

>>> sr = rsign.SignedRequest('GET', 'bp.example.com', '/test/api/v1/foos?q=bar', '443')

>>> api_key_id = 'ae71d7d92d7d4c659a7d3336db6c4c99'

>>> api_key = '7888cef675c44e8f862bae75186140d7'

>>> timestamp = str(int(time.time()))

>>> nonce = binascii.b2a_base64(os.urandom(32)).replace('\n', '')

>>> header = sr.get_signed_header(nonce, timestamp, api_key_id, api_key)

>>> header
('Authorization', 'MAC id="ae71d7d92d7d4c659a7d3336db6c4c99", ts="1400863370", nonce="Jw1ctgzz2X2n+6DDOBlEig==", mac="oYhbGKDhOZZ9ReHQyZS0jMLwOSQDGplmWbtY3d+dORM="')

>>> res = requests.get('https://bp.example.com/test/api/v1/foos?q=bar' headers=dict((header,)))

>>> res
<Response [200]>
```

### Without RSign

```
>>> import hashlib, os, requests, time, binascii, hmac

>>> method = 'GET'

>>> host = 'bp.example.com'

>>> path = '/test/api/v1/'

>>> port = '443'

>>> nonce = binascii.b2a_base64(os.urandom(32)).replace('\n', '')

>>> timestamp = str(int(time.time()))

>>> timestamp
'1400863370'

>>> api_key_id = 'ae71d7d92d7d4c659a7d3336db6c4c99'

>>> api_key = '7888cef675c44e8f862bae75186140d7'

>>> string_to_sign = '\n'.join([timestamp, nonce, method, path, host, port])

>>> string_to_sign
'1400863370\nJw1ctgzz2X2n+6DDOBlEig==\nGET\n/test/api/v1/foos?q=bar\nbp.example.com\n443'

>>> binary_signature = hmac.new(api_key, string_to_sign, hashlib.sha256).digest()

>>> base64_signature = binascii.b2a_base64(binary_signature).replace('\n','') # remove newline at end

>>> base64_signature
'oYhbGKDhOZZ9ReHQyZS0jMLwOSQDGplmWbtY3d+dORM='

>>> header = 'MAC id="{}", ts="{}", nonce="{}", mac="{}"'.format(api_key_id, timestamp, nonce, base64_signature)

>>> header
'MAC id="ae71d7d92d7d4c659a7d3336db6c4c99", ts="1400863370", nonce="Jw1ctgzz2X2n+6DDOBlEig==", mac="oYhbGKDhOZZ9ReHQyZS0jMLwOSQDGplmWbtY3d+dORM="'

>>> res = requests.get('https://bp.example.com/test/api/v1/foos?q=bar', headers={"Authorization": header})

>>> res
<Response [200]>
```

Testing
-------

- `python setup.py test`

