rsign
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

implementation notes
--------------------

- We don't use the ext field for the normalized string
- We don't append the trailing newline character ('\n') to the normalized string
- The path _should_ include query parameters if they exist, but there's no enforcement (it's not enforceable)

installation
------------

- `pip install https://github.com/cyaninc/rsign/archive/master.zip`

usage
-----

```python

from rsign import SignedRequest
from models import User
import binascii

sr = SignedRequest('GET', 'www.example.com', '/a/b/c?d=1&e=2&f=3', '443')
user = User.objects.get(id=1)
key_id = user.key_id
key = user.key
nonce = binascii.b2a_uu(os.urandom(32)).replace(' \n', '').replace('"', '')
timestamp = str(int(time.time()))
header, value = sr.get_signed_header(nonce, timestamp, key_id, key)
assert(sr.verify_signed_header(value, key))

```

examples with and without rsign
-------------------------------

API Keys were made just for this example.

### with rsign

```
>>> import rsign

>>> import requests

>>> sr = rsign.SignedRequest('GET', 'bp.example.com', '/test/api/v1/', '443')

>>> api_key_id = 'ae71d7d92d7d4c659a7d3336db6c4c99'

>>> api_key = '7888cef675c44e8f862bae75186140d7'

>>> timestamp = str(int(time.time()))

>>> nonce = binascii.b2a_uu(os.urandom(32)).replace(' \n', '').replace('"', '')

>>> header = sr.get_signed_header(nonce, timestamp, api_key_id, api_key)

>>> header
('Authorization', 'MAC id="ae71d7d92d7d4c659a7d3336db6c4c99", ts="1400863370", nonce="@.L1H=HRL<W874G\\IQ W0Z09M>G24O;\\Q[I8X\\F?Q#GH", mac="Nz4UIJLX//yR5V4ti0oQb3M37jY8lHdlmbN6wAEJ5Sk="')

>>> res = requests.get('https://bp.example.com/test/api/v1/' headers=dict((header,)))

>>> res
<Response [200]>
```

### without rsign

```
>>> import hashlib, os, requests, time, binascii, hmac

>>> method = 'GET'

>>> host = 'bp.example.com'

>>> path = '/test/api/v1/'

>>> port = '443'

>>> nonce = binascii.b2a_uu(os.urandom(32)).replace(' \n', '').replace('"', '')

>>> nonce
'@.L1H=HRL<W874G\\IQ W0Z09M>G24O;\\Q[I8X\\F?Q#GH'

>>> timestamp = str(int(time.time()))

>>> timestamp
'1400863370'

>>> api_key_id = 'ae71d7d92d7d4c659a7d3336db6c4c99'

>>> api_key = '7888cef675c44e8f862bae75186140d7'

>>> string_to_sign = '\n'.join([timestamp, nonce, method, path, host, port])

>>> string_to_sign
'1400863370\n@.L1H=HRL<W874G\\IQ W0Z09M>G24O;\\Q[I8X\\F?Q#GH\nGET\n/test/api/v1/\nbp.example.com\n443'

>>> binary_signature = hmac.new(api_key, string_to_sign, hashlib.sha256).digest()

>>> base64_signature = binascii.b2a_base64(binary_signature).replace('\n','') # remove newline at end

>>> base64_signature
'Nz4UIJLX//yR5V4ti0oQb3M37jY8lHdlmbN6wAEJ5Sk='

>>> header = 'MAC id="{}", ts="{}", nonce="{}", mac="{}"'.format(api_key_id, timestamp, nonce, base64_signature)

>>> header
'MAC id="ae71d7d92d7d4c659a7d3336db6c4c99", ts="1400863370", nonce="@.L1H=HRL<W874G\\IQ W0Z09M>G24O;\\Q[I8X\\F?Q#GH", mac="Nz4UIJLX//yR5V4ti0oQb3M37jY8lHdlmbN6wAEJ5Sk="'

>>> res = requests.get('https://bp.example.com/test/api/v1/', headers={"Authorization": header})

>>> res
<Response [200]>
```

testing
-------

- `python setup.py test`
