#!/usr/bin/env python
# coding: UTF-8
#
# Copyright (c) 2012 clowwindy
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
#
# Copyright (C) 2013-2016 Jiang Chao <sgzz.cj@gmail.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, see <http://www.gnu.org/licenses>.

import os
import hashlib
import hmac
from util import iv_checker

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from repoze.lru import lru_cache
from ctypes_libsodium import Salsa20Crypto

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


def random_string(size):
    return b'\x16\x03\x03\x00' + os.urandom(size-4)


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
    Encryptor(key, method)  # test if the settings if OK

method_supported = {
    'aes-128-cfb': (16, 16),
    'aes-192-cfb': (24, 16),
    'aes-256-cfb': (32, 16),
    # 'aes-128-ofb': (16, 16),
    # 'aes-192-ofb': (24, 16),
    # 'aes-256-ofb': (32, 16),
    # 'aes-128-ctr': (16, 16),
    # 'aes-192-ctr': (24, 16),
    # 'aes-256-ctr': (32, 16),
    'camellia-128-cfb': (16, 16),
    'camellia-192-cfb': (24, 16),
    'camellia-256-cfb': (32, 16),
    # 'camellia-128-ofb': (16, 16),
    # 'camellia-192-ofb': (24, 16),
    # 'camellia-256-ofb': (32, 16),
    'rc4-md5': (16, 16),
    'salsa20': (32, 8),
    'chacha20': (32, 8),
    'chacha20-ietf': (32, 12),
    'bypass': (16, 0),  # for testing only
}


class bypass(object):
    def __init__(self):
        pass

    def update(self, buf):
        return buf

IV_CHECKER = iv_checker(1048576, 3600)


def get_cipher(key, method, op, iv):
    if method == 'bypass':
        return bypass()
    if method in ('salsa20', 'chacha20', 'chacha20-ietf'):
        return Salsa20Crypto(method, key, iv, op)
    elif method == 'rc4-md5':
        md5 = hashlib.md5()
        md5.update(key)
        md5.update(iv)
        key = md5.digest()
        method = 'rc4'
    cipher = None

    if method.startswith('rc4'):
        pass
    elif method.endswith('ctr'):
        mode = modes.CTR(iv)
    elif method.endswith('ofb'):
        mode = modes.OFB(iv)
    elif method.endswith('cfb'):
        mode = modes.CFB(iv)
    else:
        raise ValueError('operation mode "%s" not supported!' % method.upper())

    if method.startswith('rc4'):
        cipher = Cipher(algorithms.ARC4(key), None, default_backend())
    elif method.startswith('aes'):
        cipher = Cipher(algorithms.AES(key), mode, default_backend())
    elif method.startswith('camellia'):
        cipher = Cipher(algorithms.Camellia(key), mode, default_backend())
    else:
        raise ValueError('crypto algorithm "%s" not supported!' % method.upper())

    return cipher.encryptor() if op else cipher.decryptor()


class Encryptor(object):
    def __init__(self, password, method=None, servermode=False):
        if method not in method_supported:
            raise ValueError('encryption method not supported')
        if not isinstance(password, bytes):
            password = password.encode('utf8')
        self.key = password
        self.method = method
        self.servermode = servermode
        self.iv_sent = False
        self.decipher = None

        self.key_len, self.iv_len = method_supported.get(method)
        self.key = EVP_BytesToKey(password, self.key_len)
        self.cipher_iv = random_string(self.iv_len) if self.iv_len else b''
        self.cipher = get_cipher(self.key, method, 1, self.cipher_iv)

    def encrypt(self, buf):
        if len(buf) == 0:
            raise ValueError('buf should not be empty')
        if self.iv_sent:
            return self.cipher.update(buf)
        else:
            self.iv_sent = True
            return self.cipher_iv + self.cipher.update(buf)

    def decrypt(self, buf):
        if len(buf) == 0:
            raise ValueError('buf should not be empty')
        if self.decipher is None:
            decipher_iv = buf[:self.iv_len]
            if self.servermode:
                IV_CHECKER.check(self.key, decipher_iv)
            self.decipher = get_cipher(self.key, self.method, 0, decipher_iv)
            buf = buf[self.iv_len:]
            if len(buf) == 0:
                return buf
        return self.decipher.update(buf)


@lru_cache(128)
def hkdf(key, salt, ctx, key_len):
    '''
    consider key come from a key exchange protocol.
    '''
    key = hmac.new(salt, key, hashlib.sha256).digest()
    sek = hmac.new(key, ctx + b'server_encrypt_key', hashlib.sha256).digest()[:key_len]
    sak = hmac.new(key, ctx + b'server_authenticate_key', hashlib.sha256).digest()
    cek = hmac.new(key, ctx + b'client_encrypt_key', hashlib.sha256).digest()[:key_len]
    cak = hmac.new(key, ctx + b'client_authenticate_key', hashlib.sha256).digest()
    return sek, sak, cek, cak


key_len_to_hash = {
    16: hashlib.md5,
    24: hashlib.sha1,
    32: hashlib.sha256,
}


class AEncryptor(object):
    '''
    Provide Authenticated Encryption
    '''
    def __init__(self, key, method, salt, ctx, servermode):
        if method not in method_supported:
            raise ValueError('encryption method not supported')
        self.method = method
        self.servermode = servermode
        self.key_len, self.iv_len = method_supported.get(method)
        if servermode:
            self.encrypt_key, self.auth_key, self.decrypt_key, self.de_auth_key = hkdf(key, salt, ctx, self.key_len)
        else:
            self.decrypt_key, self.de_auth_key, self.encrypt_key, self.auth_key = hkdf(key, salt, ctx, self.key_len)
        hfunc = key_len_to_hash[self.key_len]
        self.iv_sent = False
        self.cipher_iv = random_string(self.iv_len) if self.iv_len else b''
        self.cipher = get_cipher(self.encrypt_key, method, 1, self.cipher_iv)
        self.decipher = None
        self.enmac = hmac.new(self.auth_key, digestmod=hfunc)
        self.demac = hmac.new(self.de_auth_key, digestmod=hfunc)

    def encrypt(self, buf, ad=None):
        if len(buf) == 0:
            raise ValueError('buf should not be empty')
        if self.iv_sent:
            ct = self.cipher.update(buf)
        else:
            self.iv_sent = True
            ct = self.cipher_iv + self.cipher.update(buf)
        if ad:
            self.enmac.update(ad)
        self.enmac.update(ct)
        return ct, self.enmac.digest()

    def decrypt(self, buf, mac, ad=None):
        if len(buf) == 0:
            raise ValueError('buf should not be empty')
        if ad:
            self.demac.update(ad)
        self.demac.update(buf)
        rmac = self.demac.digest()
        if self.decipher is None:
            decipher_iv = buf[:self.iv_len]
            self.decipher = get_cipher(self.decrypt_key, self.method, 0, decipher_iv)
            buf = buf[self.iv_len:]
        pt = self.decipher.update(buf) if buf else b''
        if compare_digest(rmac, mac):
            return pt
        raise ValueError('MAC verification failed!')

if __name__ == '__main__':
    print('encrypt and decrypt 20MB data.')
    s = os.urandom(10240)
    import time
    lst = sorted(method_supported.keys())
    for method in lst:
        try:
            cipher = Encryptor(b'123456', method)
            t = time.clock()
            for _ in range(1024):
                a = cipher.encrypt(s)
                b = cipher.encrypt(s)
                c = cipher.decrypt(a)
                d = cipher.decrypt(b)
            print('%s %ss' % (method, time.clock() - t))
        except Exception as e:
            print(repr(e))
    print('test AE')
    ae1 = AEncryptor(b'123456', 'aes-256-cfb', b'salt', b'ctx', False)
    ae2 = AEncryptor(b'123456', 'aes-256-cfb', b'salt', b'ctx', True)
    a, b = ae1.encrypt(b'abcde')
    c, d = ae1.encrypt(b'fg')
    print(ae2.decrypt(a, b))
    print(ae2.decrypt(c, d))
    for method in lst:
        try:
            cipher1 = AEncryptor(b'123456', method, b'salt', b'ctx', False)
            cipher2 = AEncryptor(b'123456', method, b'salt', b'ctx', True)
            t = time.clock()
            for _ in range(1024):
                a, b = cipher1.encrypt(s)
                c, d = cipher1.encrypt(s)
                cipher2.decrypt(a, b)
                cipher2.decrypt(c, d)
            print('%s-HMAC %ss' % (method, time.clock() - t))
        except Exception as e:
            print(repr(e))
