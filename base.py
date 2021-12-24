from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint
from blake3 import blake3

def int_to_bytes(x: int) -> bytes:
	return x.to_bytes()
	#return x.to_bytes((x.bit_length() + 7) // 8, 'big')
    
def bytes_to_int(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, 'big')


# https://neuromancer.sk/std/nist/P-256

n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

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


class ECC_G():
	def __init__(self):
		pass

	def generate(self):
		self.g = ECC.generate(curve='p256').pointQ
		self.h = ECC.generate(curve='p256').pointQ


	def get_public(self):
		return (self.g,self.h)



class SR_Oracle():
	def __init__(self,g,h):
		self.g = g
		self.h = h
		self.k_sr = bytes_to_int(get_random_bytes(32))

	def compute_intermediate_rule(self,Ri):
		return Ri*self.k_sr

	def compute_obfuscated_tokens(self,ti_list):
		Ti_list=[]
		c = randint(0,2**64)
		for i in range(len(ti_list)):
			encrypted = int_to_bytes(self._encrypt(ti_list[i]).x)
			Ti_list.append(H2(c+i,encrypted))
		return (c,Ti_list)

	def _encrypt(self,msg):
		return (g*bytes_to_int(H1(msg))+h)*self.k_sr


k_mb = bytes_to_int(get_random_bytes(32))


RG = ECC_G()
RG.generate()

g,h = RG.get_public()


Rrg = g*k_mb
Rrh = h*k_mb


SR = SR_Oracle(g,h)
Irg = SR.compute_intermediate_rule(Rrg)
Irh = SR.compute_intermediate_rule(Rrh)


k_mb_inv = pow(k_mb,n-2,n)

Srg = Irg*k_mb_inv
Srh = Irh*k_mb_inv


c,Ti=SR.compute_obfuscated_tokens([b'Test'])

Ti = Ti[0]

forged_encryption = Srg*bytes_to_int(H1(b'Test'))+Srh

Ti_forged = H2(c,int_to_bytes(forged_encryption.x))

print("Done.")
print("Ti:",Ti)
print("Forged Ti:",Ti_forged)
assert Ti ==  Ti_forged