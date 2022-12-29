from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint
import base64 as b64
import traffic
import ecdsa
from p2dpilib import *

secure_message = traffic.get_msg()

sign_pub= None
with open('key.pub','rb') as f:
	sign_pub=f.read()
ver=ecdsa.VerifyingKey.from_pem(sign_pub)

def get_ecc_point():
	p = input().split(' ')
	return ECC.EccPoint(int(p[0],16),int(p[1],16))

class SR_Oracle():
	def __init__(self,g,h):
		self.g = g
		self.h = h
		self.k_sr = bytes_to_int(get_random_bytes(32))

	def compute_intermediate_rule(self,Ri):
		return Ri*self.k_sr

	def compute_obfuscated_tokens(self,ti_list):
		Ti_list=[]
		c = randint(0,2**32)
		for i in range(len(ti_list)):
			encrypted = int_to_bytes(self._encrypt(ti_list[i]).x)
			Ti_list.append(H2(c+i,encrypted))
		return (c,Ti_list)

	def _encrypt(self,msg):
		return (g*bytes_to_int(H1(msg))+h)*self.k_sr


if __name__ == '__main__':
	g = get_ecc_point()
	h = get_ecc_point()

	SR = SR_Oracle(g,h)

	try:
		while True:
			print("Query:")
			print("1. Obfuscate rule ")
			print("2. Get traffic")
			i = input().strip()
			if i == '1':
				R = input().strip()
				Rinit = R.encode('utf-8')
				R = R.split(' ')
				R = ECC.EccPoint(int(R[0],16),int(R[1],16))
				sig = bytes.fromhex(input().strip())

				if R == g or R == h:
					print("Rule entropy too small.")
					exit()

				if not ver.verify(sig,Rinit):
					exit()

				s1 = SR.compute_intermediate_rule(R)
				print(hex(s1.x)[2:],hex(s1.y)[2:])
			elif i == '2':
				c,Ti=SR.compute_obfuscated_tokens(tokenize(secure_message))
				print(str(c)+' ',end='')
				print(b''.join(Ti).hex())
			else:
				exit()
	except:
		exit()
