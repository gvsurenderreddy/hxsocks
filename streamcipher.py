#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2012-2014 Jiang Chao <sgzz.cj@gmail.com>
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

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class StreamCipher(object):
    def __init__(self, method, key, iv, mode):
        self.method = method
        self.key = key
        self.iv = iv
        self.iv_len = len(iv)
        self.cipher = self.get_cipher().encryptor() if mode else self.get_cipher().decryptor()
        self.update = self.cipher.update

    def get_cipher(self):
        if self.method.startswith('rc4'):
            return Cipher(algorithms.ARC4(self.key), None, default_backend())
        if self.method.endswith('ctr'):
            mode = modes.CTR(self.iv)
        elif self.method.endswith('ofb'):
            mode = modes.OFB(self.iv)
        elif self.method.endswith('cfb'):
            mode = modes.CFB(self.iv)
        else:
            raise ValueError('operation mode %s not supported!' % self.method.upper())
        if self.method.startswith('aes'):
            return Cipher(algorithms.AES(self.key), mode, default_backend())
        if self.method.startswith('camellia'):
            return Cipher(algorithms.Camellia(self.key), mode, default_backend())
        if self.method.startswith('seed'):
            return Cipher(algorithms.SEED(self.key), mode, default_backend())
        raise ValueError('crypto algorithm %s not supported!' % self.method)
