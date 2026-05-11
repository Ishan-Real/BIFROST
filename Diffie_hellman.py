import secrets
import Math_Utils

class DiffieHellman:
    def __init__(self, prime, generator):
        self.p = prime
        self.g = generator
        self.private_key = None
        self.public_key = None
        self.shared_secret = None

    def generate_keys(self):
        self.private_key = secrets.randbits(256)
        
        # Calculate Public Key: (g^privateKey) mod p
        self.public_key = Math_Utils.mod_exp(self.g, self.private_key, self.p)

    def get_public_key(self):
        return self.public_key

    def compute_shared_secret(self, other_public_key):
        # Calculate Shared Secret: (otherPublicKey^privateKey) mod p
        self.shared_secret = Math_Utils.mod_exp(other_public_key, self.private_key, self.p)

    def get_shared_secret(self):
        return self.shared_secret