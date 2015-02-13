#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

import random
from M2Crypto import EC


class DH(object):
    size = 512
    curve5 = EC.NID_secp521r1
    curve2 = EC.NID_secp256k1

    def __init__(self):
        self.ec = EC.gen_params(self.curve2)
        self.ec.gen_key()

    def getPubKey(self):
        return self.ec.pub().get_der()[:]

    def genKey(self, otherKey):
        buf = buffer(otherKey)
        pk = EC.pub_key_from_der(buf)
        return self.ec.compute_dh_key(pk)


if __name__ == '__main__':
    import time
    t = time.time()
    alice = DH()
    bob = DH()
    print(repr(alice.genKey(bob.getPubKey())))
    print(repr(bob.genKey(alice.getPubKey())))
    print('DH: %fs' % (time.time() - t))
