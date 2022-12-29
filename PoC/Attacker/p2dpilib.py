from Crypto.PublicKey import ECC
from blake3 import blake3

n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551


def int_to_bytes(x: int) -> bytes:
	return x.to_bytes()
    
def bytes_to_int(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, 'big')

def int_arr_to_bytes(m):
	return b''.join([x.to_bytes(1,'big') for x in m])

def H1(msg):
	hasher = blake3()
	hasher.update(b'Salty')
	hasher.update(msg)
	return hasher.digest()

def H2(c, msg):
	hasher = blake3()
	hasher.update(int.to_bytes(c,32,'big'))
	hasher.update(msg)
	return hasher.digest()

def tokenize(msg):
	return [msg[i:i+8] for i in range(len(msg)-8)]

class ECC_G():
	def __init__(self):
		pass

	def generate(self):
		self.g = ECC.generate(curve='p256').pointQ
		self.h = ECC.generate(curve='p256').pointQ

	def get_public(self):
		return (self.g,self.h)
