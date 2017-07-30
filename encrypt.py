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
import sys
import hashlib
import hmac
import struct

from util import iv_checker

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ctypes_libsodium import Salsa20Crypto

try:
    from hmac import compare_digest
except ImportError:
    def compare_digest(a, b):
        # if a and b are identical, return True
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
    return os.urandom(size)


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
    # 'bypass': (16, 16),  # for testing only

    # 'aes-128-gcm': (16, 16),
    # 'aes-192-gcm': (24, 24),
    # 'aes-256-gcm': (32, 32),
    # 'chacha20_poly1305': (32, 12),
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
    def __init__(self, password, method):
        if method not in method_supported:
            raise ValueError('encryption method not supported')
        if not isinstance(password, bytes):
            password = password.encode('utf8')
        self.method = method
        self.iv_sent = False

        self.key_len, self.iv_len = method_supported.get(method)
        self.__key = EVP_BytesToKey(password, self.key_len)

        while True:
            iv = random_string(self.iv_len)
            try:
                IV_CHECKER.check(self.__key, iv)
            except ValueError:
                continue
            break
        self.cipher_iv = iv
        self.cipher = get_cipher(self.__key, method, 1, self.cipher_iv)
        self.decipher = None

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
            iv = buf[:self.iv_len]
            IV_CHECKER.check(self.__key, iv)
            self.decipher = get_cipher(self.__key, self.method, 0, iv)
            del self.__key
            buf = buf[self.iv_len:]
            if len(buf) == 0:
                return
        return self.decipher.update(buf)


key_len_to_hash = {
    16: hashlib.md5,
    24: hashlib.sha1,
    32: hashlib.sha256,
}


class AEncryptor(object):
    '''
    Provide Authenticated Encryption
    '''
    def __init__(self, key, method, ctx):
        if method not in method_supported:
            raise ValueError('encryption method not supported')
        self.method = method
        self.__key = key
        self.key_len, self.iv_len = method_supported.get(method)
        self.mac_len = 16
        self.iv_sent = False
        self.hfunc = key_len_to_hash[self.key_len]

        while True:
            iv = random_string(self.iv_len)
            try:
                IV_CHECKER.check(self.__key, iv)
            except ValueError:
                continue
            break
        self.cipher_iv = iv

        encrypt_key = hmac.new(key, self.cipher_iv, hashlib.sha256).digest()[:self.key_len]
        self.__encrypt_auth_key = hmac.new(key, encrypt_key, hashlib.sha256).digest()[:self.key_len]
        self.__encrypt_seq = 0
        self.cipher = get_cipher(encrypt_key, method, 1, self.cipher_iv)

        self.decipher = None
        self.__decrypt_auth_key = None
        self.__decrypt_seq = 0

    def encrypt(self, buf, ad=None):
        if len(buf) == 0:
            raise ValueError('buf should not be empty')
        if self.iv_sent:
            ct = self.cipher.update(buf)
        else:
            self.iv_sent = True
            ct = self.cipher_iv + self.cipher.update(buf)

        enmac = hmac.new(self.__encrypt_auth_key, digestmod=self.hfunc)
        enmac.update(struct.pack('!Q', self.__encrypt_seq))
        self.__encrypt_seq += 1
        enmac.update(ct)
        if ad:
            enmac.update(ad)
        return ct + enmac.digest()[:self.mac_len]

    def decrypt(self, buf, ad=None):
        if len(buf) == 0:
            raise ValueError('buf should not be empty')
        if self.decipher is None:
            iv, buf = buf[:self.iv_len], buf[self.iv_len:]
            IV_CHECKER.check(self.__key, iv)
            decrypt_key = hmac.new(self.__key, iv, hashlib.sha256).digest()[:self.key_len]
            self.__decrypt_auth_key = hmac.new(self.__key, decrypt_key, hashlib.sha256).digest()[:self.key_len]
            self.decipher = get_cipher(decrypt_key, self.method, 0, iv)
            del self.__key

        demac = hmac.new(self.__decrypt_auth_key, digestmod=self.hfunc)
        demac.update(struct.pack('!Q', self.__decrypt_seq))
        if self.__decrypt_seq == 0:
            demac.update(iv)
        self.__decrypt_seq += 1
        buf, mac = buf[:self.mac_len * -1], buf[self.mac_len * -1:]
        demac.update(buf)
        if ad:
            demac.update(ad)
        rmac = demac.digest()[:self.mac_len]
        pt = self.decipher.update(buf) if buf else b''
        if compare_digest(rmac, mac):
            return pt
        raise ValueError('MAC verification failed!')


if sys.version_info[0] == 3:
    def buffer(x):
        return x


class AEncryptor_GCM(object):
    '''
    Provide Authenticated Encryption, compatible with shadowsocks AEAD mode.
    '''
    def __init__(self, key, method, ctx):
        if method not in method_supported:
            raise ValueError('encryption method not supported')
        self.method = method
        self.algorithm = self.select_algo(method)
        self._ctx = ctx
        self.__key = key
        self._key_len, self._iv_len = method_supported.get(method)
        self._nonce_len = 12
        self._tag_len = 16
        self.iv_sent = False

        while True:
            iv = random_string(self._iv_len)
            try:
                IV_CHECKER.check(key, iv)
            except ValueError:
                continue
            break
        self._encryptor_iv = iv
        self._encryptor_skey = self.key_expand(key, self._encryptor_iv, hashlib.sha1)
        self._encryptor_nonce = 0

        self._decryptor_skey = None
        self._decryptor_nonce = 0

    def select_algo(self, method):
        if method.startswith('aes'):
            return algorithms.AES
        raise ValueError('encryption method not supported')

    def key_expand(self, key, iv, algo):
        prk = hmac.new(iv, key, algo).digest()

        hash_len = algo().digest_size
        blocks_needed = self._key_len // hash_len + (1 if self._key_len % hash_len else 0)  # ceil
        okm = b""
        output_block = b""
        for counter in range(blocks_needed):
            output_block = hmac.new(prk,
                                    buffer(output_block + self._ctx + bytearray((counter + 1,))),
                                    algo
                                    ).digest()
            okm += output_block
        return okm[:self._key_len]

    def encrypt(self, buf, ad=None):
        '''
        TCP Chunk (after encryption, *ciphertext*)
        +--------------+------------+
        |    *Data*    |  Data_TAG  |
        +--------------+------------+
        |   Variable   |   Fixed    |
        +--------------+------------+
        for shadowsocks AEAD, this method must be called twice:
        first encrypt Data_Len, then encrypt Data

        '''
        if len(buf) == 0:
            raise ValueError('buf should not be empty')
        nonce = struct.pack('<Q', self._encryptor_nonce) + b'\x00\x00\x00\x00'
        self._encryptor_nonce += 1
        encryptor = Cipher(self.algorithm(self._encryptor_skey),
                           modes.GCM(nonce),
                           backend=default_backend()).encryptor()
        if ad:
            encryptor.authenticate_additional_data(ad)
        ct = encryptor.update(buf) + encryptor.finalize() + encryptor.tag
        if not self.iv_sent:
            self.iv_sent = True
            ct = self._encryptor_iv + ct
        return ct

    def decrypt(self, buf, ad=None):
        if len(buf) == 0:
            raise ValueError('buf should not be empty')

        ct, tag = buf[:self._tag_len * -1], buf[self._tag_len * -1:]

        if self._decryptor_skey is None:
            iv, ct = ct[:self._iv_len], ct[self._iv_len:]
            IV_CHECKER.check(self.__key, iv)
            self._decryptor_skey = self.key_expand(self.__key, iv, hashlib.sha1)
            del self.__key

        nonce = struct.pack('<Q', self._decryptor_nonce) + b'\x00\x00\x00\x00'
        self._decryptor_nonce += 1
        decryptor = Cipher(self.algorithm(self._decryptor_skey),
                           modes.GCM(nonce, tag),
                           backend=default_backend()).decryptor()
        if ad:
            decryptor.authenticate_additional_data(ad)

        return decryptor.update(ct) + decryptor.finalize()


if __name__ == '__main__':
    # disable ivchecker

    class ivchecker(object):
        def __init__(self, size, timeout):
            pass

        def check(self, key, iv):
            pass

    method_supported.update({'aes-128-gcm': (16, 16),
                             'aes-192-gcm': (24, 24),
                             'aes-256-gcm': (32, 32), })

    IV_CHECKER = ivchecker(1, 1)

    print('encrypt and decrypt 20MB data.')
    s = os.urandom(10240)
    import time
    lst = sorted(method_supported.keys())
    for method in lst:
        if method.endswith('gcm'):
            continue
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
    print('test AE HMAC')
    ae1 = AEncryptor(b'123456', 'aes-256-cfb', b'ctx')
    ae2 = AEncryptor(b'123456', 'aes-256-cfb', b'ctx')
    ct1 = ae1.encrypt(b'abcde')
    ct2 = ae1.encrypt(b'fg')
    print(ae2.decrypt(ct1))
    print(ae2.decrypt(ct2))
    for method in lst:
        if method.endswith('gcm'):
            continue
        try:
            cipher1 = AEncryptor(b'123456', method, b'ctx')
            cipher2 = AEncryptor(b'123456', method, b'ctx')
            t = time.clock()
            for _ in range(1024):
                ct1 = cipher1.encrypt(s)
                ct2 = cipher1.encrypt(s)
                cipher2.decrypt(ct1)
                cipher2.decrypt(ct2)
            print('%s-HMAC %ss' % (method, time.clock() - t))
        except Exception as e:
            print(repr(e))
    print('test AE GCM')
    ae1 = AEncryptor_GCM(b'123456', 'aes-256-gcm', b'ctx')
    ae2 = AEncryptor_GCM(b'123456', 'aes-256-gcm', b'ctx')
    ct1 = ae1.encrypt(b'abcde')
    ct2 = ae1.encrypt(b'fg')
    print(ae2.decrypt(ct1))
    print(ae2.decrypt(ct2))
    for method in lst:
        if not method.endswith('gcm'):
            continue
        try:
            cipher1 = AEncryptor_GCM(b'123456', method, b'ctx')
            cipher2 = AEncryptor_GCM(b'123456', method, b'ctx')
            t = time.clock()
            for _ in range(1024):
                ct1 = cipher1.encrypt(s)
                ct2 = cipher1.encrypt(s)
                cipher2.decrypt(ct1)
                cipher2.decrypt(ct2)
            print('%s %ss' % (method, time.clock() - t))
        except Exception as e:
            print(repr(e))
