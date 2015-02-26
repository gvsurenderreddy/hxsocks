#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

from M2Crypto import EC


class ECC(object):
    curve = {256: EC.NID_secp521r1,
             192: EC.NID_secp384r1,
             128: EC.NID_secp256k1,
             32: EC.NID_secp521r1,
             24: EC.NID_secp384r1,
             16: EC.NID_secp256k1,
             }

    def __init__(self, key_len=128, from_file=None):
        if from_file:
            self.ec = EC.load_key(from_file)
        else:
            self.ec = EC.gen_params(self.curve[key_len])
            self.ec.gen_key()

    def get_pub_key(self):
        return self.ec.pub().get_der()[:]

    def get_dh_key(self, otherKey):
        pk = EC.pub_key_from_der(buffer(otherKey))
        return self.ec.compute_dh_key(pk)

    def save(self, dest):
        self.ec.save_key(dest, cipher=None)

    def sign(self, digest):
        '''Sign the given digest using ECDSA. Returns a tuple (r,s), the two ECDSA signature parameters.'''
        return self.ec.sign_dsa(digest)

    def verify(self, digest, r, s):
        '''Verify the given digest using ECDSA. r and s are the ECDSA signature parameters.
           if verified, return 1.
        '''
        return self.ec.verify_dsa(digest, r, s)

    @staticmethod
    def verify_with_pub_key(pubkey, digest, r, s):
        '''Verify the given digest using ECDSA. r and s are the ECDSA signature parameters.
           if verified, return 1.
        '''
        if isinstance(pubkey, bytes):
            pubkey = EC.pub_key_from_der(buffer(pubkey))
        return pubkey.verify_dsa(digest, r, s)

    @staticmethod
    def save_pub_key(pubkey, dest):
        pubk = EC.pub_key_from_der(buffer(pubkey))
        pubk.save_pub_key(dest)

if __name__ == '__main__':
    import time
    t = DH()
    t = time.time()
    alice = DH()
    bob = DH()
    print(repr(alice.genKey(bob.getPubKey())))
    print(repr(bob.genKey(alice.getPubKey())))
    print('ECDH: %fs' % (time.time() - t))
