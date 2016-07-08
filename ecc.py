from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_der_private_key,\
    load_der_public_key, Encoding, PublicFormat, PrivateFormat, NoEncryption


class ECC(object):
    curve = {256: ec.SECP521R1,
             192: ec.SECP384R1,
             128: ec.SECP256R1,
             32: ec.SECP521R1,
             24: ec.SECP384R1,
             16: ec.SECP256R1,
             }

    def __init__(self, key_len=128, from_file=None):
        if from_file:
            with open(from_file, 'rb') as f:
                data = f.read()
            if data.startswith(b'-----'):
                self.ec_private = load_pem_private_key(data, None, backend=default_backend())
            else:
                self.ec_private = load_der_private_key(data, backend=default_backend())
        else:
            self.ec_private = ec.generate_private_key(self.curve[key_len](), default_backend())
        self.ec_public = self.ec_private.public_key()

    def get_pub_key(self):
        return self.ec_public.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    def get_dh_key(self, otherKey):
        peer_public_key = load_der_public_key(otherKey, backend=default_backend())
        return self.ec_private.exchange(ec.ECDH(), peer_public_key)

    def save(self, dest):
        data = self.ec_private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        with open(dest, 'wb') as f:
            f.write(data)

    def sign(self, data, hash_algo):
        '''Sign the given digest using ECDSA. Returns a signature.'''
        signer = self.ec_private.signer(ec.ECDSA(getattr(hashes, hash_algo)()))
        signer.update(data)
        signature = signer.finalize()
        return signature

    def verify(self, data, signature, hash_algo):
        '''Verify the given digest using ECDSA. r and s are the ECDSA signature parameters.
           if verified, return 1.
        '''
        verifier = self.ec_public.verifier(signature, ec.ECDSA(getattr(hashes, hash_algo)()))
        verifier.update(data)
        try:
            verifier.verify()
            return 1
        except:
            return 0

    @staticmethod
    def verify_with_pub_key(pubkey, data, signature, hash_algo):
        '''Verify the given digest using ECDSA. r and s are the ECDSA signature parameters.
           if verified, return 1.
        '''
        pubkey = load_der_public_key(pubkey, backend=default_backend())
        verifier = pubkey.verifier(signature, ec.ECDSA(getattr(hashes, hash_algo)()))
        verifier.update(data)
        try:
            verifier.verify()
            return 1
        except:
            return 0

    @staticmethod
    def save_pub_key(pubkey, dest):
        pubk = load_der_public_key(pubkey)
        data = pubk.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        with open(dest, 'wb') as f:
            f.write(data)
