#!/usr/bin/env python

# Copyright (c) 2012 clowwindy
# Copyright (c) 2013 - 2015 v3aqb
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
import hashlib
import hmac
import string
import struct
from collections import defaultdict, deque
from repoze.lru import lru_cache
from ctypes_libsodium import Salsa20Crypto
try:
    from M2Crypto.EVP import Cipher
    import M2Crypto.Rand
    random_string = M2Crypto.Rand.rand_bytes
except ImportError:
    random_string = os.urandom
    try:
        from streamcipher import StreamCipher as Cipher
    except ImportError:
        Cipher = None
try:
    from hmac import compare_digest
except ImportError:
    def compare_digest(a, b):
        if isinstance(a, str):
            if len(a) != len(b):
                return False
            result = 0
            for x, y in zip(a, b):
                result |= ord(x) ^ ord(y)
            return result == 0
        else:
            if len(a) != len(b):
                return False
            result = 0
            for x, y in zip(a, b):
                result |= x ^ y
            return result == 0


def get_table(key):
    m = hashlib.md5()
    m.update(key)
    s = m.digest()
    (a, b) = struct.unpack('<QQ', s)
    table = [c for c in string.maketrans('', '')]
    for i in range(1, 1024):
        table.sort(lambda x, y: int(a % (ord(x) + i) - a % (ord(y) + i)))
    return table


@lru_cache(128)
def init_table(key):
    encrypt_table = ''.join(get_table(key))
    decrypt_table = string.maketrans(encrypt_table, string.maketrans('', ''))
    return (encrypt_table, decrypt_table)


@lru_cache(128)
def EVP_BytesToKey(password, key_len):
    # equivalent to OpenSSL's EVP_BytesToKey() with count 1
    # so that we make the same key and iv as nodejs version
    m = []
    l = 0
    while l < key_len:
        md5 = hashlib.md5()
        data = password
        if len(m) > 0:
            data = m[len(m) - 1] + password
        md5.update(data)
        m.append(md5.digest())
        l += 16
    ms = b''.join(m)
    return ms[:key_len]


def check(key, method):
    if method.lower() == 'table':
        init_table(key)
    else:
        Encryptor(key, method)  # test if the settings if OK

method_supported = {
    'aes-128-cfb': (16, 16),
    'aes-192-cfb': (24, 16),
    'aes-256-cfb': (32, 16),
    'aes-128-ofb': (16, 16),
    'aes-192-ofb': (24, 16),
    'aes-256-ofb': (32, 16),
    'rc4': (16, 0),
    'rc4-md5': (16, 16),
    'salsa20': (32, 8),
    'chacha20': (32, 8),
}


def get_cipher_len(method):
    return method_supported.get(method.lower(), None)


class sized_deque(deque):
    def __init__(self):
        deque.__init__(self, maxlen=1048576)

USED_IV = defaultdict(sized_deque)


def create_rc4_md5(method, key, iv, op):
    md5 = hashlib.md5()
    md5.update(key)
    md5.update(iv)
    rc4_key = md5.digest()
    return Cipher('rc4', rc4_key, '', op)


def get_cipher(key, method, op, iv):
    if method == 'rc4-md5':
        return create_rc4_md5(method, key, iv, op)
    elif method in ('salsa20', 'chacha20'):
        return Salsa20Crypto(method, key, iv, op)
    else:
        return Cipher(method.replace('-', '_'), key, iv, op)


class Encryptor(object):
    def __init__(self, password, method=None, servermode=False):
        if method == 'table':
            method = None
        self.key = password
        self.method = method
        self.servermode = servermode
        self.iv_len = 0
        self.iv_sent = False
        self.cipher_iv = b''
        self.decipher = None
        if method is not None:
            klen, self.iv_len = get_cipher_len(method)
            self.key = EVP_BytesToKey(password, klen)
            self.cipher_iv = random_string(self.iv_len)
            self.cipher = get_cipher(self.key, method, 1, self.cipher_iv)
        else:
            self.cipher = None
            self.decipher = 0
            self.encrypt_table, self.decrypt_table = init_table(password)

    def encrypt(self, buf):
        if len(buf) == 0:
            raise ValueError('buf should not be empty')
        if self.method is None:
            return string.translate(buf, self.encrypt_table)
        else:
            if self.iv_sent:
                return self.cipher.update(buf)
            else:
                self.iv_sent = True
                return self.cipher_iv + self.cipher.update(buf)

    def decrypt(self, buf):
        if len(buf) == 0:
            raise ValueError('buf should not be empty')
        if self.method is None:
            return string.translate(buf, self.decrypt_table)
        else:
            if self.decipher is None:
                decipher_iv = buf[:self.iv_len]
                if self.servermode:
                    if decipher_iv in USED_IV[self.key]:
                        raise ValueError('iv reused, possible replay attrack')
                    USED_IV[self.key].append(decipher_iv)
                self.decipher = get_cipher(self.key, self.method, 0, decipher_iv)
                buf = buf[self.iv_len:]
                if len(buf) == 0:
                    return buf
            return self.decipher.update(buf)


class AEncryptor(object):
    '''
    Provide Authenticated Encryption
    '''
    def __init__(self, key, method, salt, ctx, servermode, hfunc=hashlib.md5):
        if method not in method_supported:
            raise ValueError('method not supported')
        self.method = method
        self.servermode = servermode
        self.key_len, self.iv_len = get_cipher_len(method)
        if servermode:
            self.encrypt_key, self.auth_key, self.decrypt_key, self.de_auth_key = self.hkdf(key, salt, ctx)
        else:
            self.decrypt_key, self.de_auth_key, self.encrypt_key, self.auth_key = self.hkdf(key, salt, ctx)
        self.iv_sent = False
        self.cipher_iv = random_string(self.iv_len)
        self.cipher = get_cipher(self.encrypt_key, method, 1, self.cipher_iv)
        self.decipher = None
        self.enmac = hmac.new(self.auth_key, digestmod=hfunc)
        self.demac = hmac.new(self.de_auth_key, digestmod=hfunc)

    def hkdf(self, key, salt, ctx):
        '''
        consider key come from a key exchange protocol.
        '''
        key = hmac.new(salt, key, hashlib.sha256).digest()
        sek = hmac.new(key, ctx + b'server_encrypt_key', hashlib.sha256).digest()[:self.key_len]
        sak = hmac.new(key, ctx + b'server_authenticate_key', hashlib.sha256).digest()
        cek = hmac.new(key, ctx + b'client_encrypt_key', hashlib.sha256).digest()[:self.key_len]
        cak = hmac.new(key, ctx + b'client_authenticate_key', hashlib.sha256).digest()
        return sek, sak, cek, cak

    def encrypt(self, buf):
        if len(buf) == 0:
            raise ValueError('buf should not be empty')
        if self.method is None:
            return string.translate(buf, self.encrypt_table)
        else:
            if self.iv_sent:
                ct = self.cipher.update(buf)
            else:
                self.iv_sent = True
                ct = self.cipher_iv + self.cipher.update(buf)
            self.enmac.update(ct)
            return ct, self.enmac.digest()

    def decrypt(self, buf, mac):
        if len(buf) == 0:
            raise ValueError('buf should not be empty')
        self.demac.update(buf)
        rmac = self.demac.digest()
        if self.decipher is None:
            decipher_iv = buf[:self.iv_len]
            if self.servermode:
                if decipher_iv in USED_IV[self.decrypt_key]:
                    raise ValueError('iv reused, possible replay attrack')
                USED_IV[self.decrypt_key].append(decipher_iv)
            self.decipher = get_cipher(self.decrypt_key, self.method, 0, decipher_iv)
            buf = buf[self.iv_len:]
        pt = self.decipher.update(buf) if buf else b''
        if compare_digest(rmac, mac):
            return pt
        raise ValueError('MAC verification failed!')

if __name__ == '__main__':
    print('encrypt and decrypt 20MB data.')
    s = os.urandom(10000)
    import time
    lst = sorted(method_supported.keys())
    for method in lst:
        try:
            cipher = Encryptor('123456', method)
            t = time.time()
            for _ in range(1049):
                a = cipher.encrypt(s)
                b = cipher.encrypt(s)
                c = cipher.decrypt(a)
                d = cipher.decrypt(b)
            print('%s %ss' % (method, time.time() - t))
        except Exception as e:
            print(repr(e))
    print('test AE')
    ae1 = AEncryptor(b'123456', 'aes-256-cfb', 'salt', 'ctx', False, hashlib.sha256)
    ae2 = AEncryptor(b'123456', 'aes-256-cfb', 'salt', 'ctx', True, hashlib.sha256)
    a, b = ae1.encrypt(b'abcde')
    c, d = ae1.encrypt(b'fg')
    print(ae2.decrypt(a, b))
    print(ae2.decrypt(c, d))
    for method in lst:
        try:
            cipher1 = AEncryptor(b'123456', method, 'salt', 'ctx', False, hashlib.md5,)
            cipher2 = AEncryptor(b'123456', method, 'salt', 'ctx', True, hashlib.md5)
            t = time.time()
            for _ in range(1049):
                a, b = cipher1.encrypt(s)
                c, d = cipher1.encrypt(s)
                cipher2.decrypt(a, b)
                cipher2.decrypt(c, d)
            print('%s-HMAC-MD5 %ss' % (method, time.time() - t))
        except Exception as e:
            print(repr(e))
