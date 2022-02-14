from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint
from blake3 import blake3
import base64 as b64
from pwn import *
import os
import ecdsa


sign_priv= None
with open('key.priv','rb') as f:
	sign_priv=f.read()
sig=ecdsa.SigningKey.from_pem(sign_priv)


printable=b'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r'

def int_to_bytes(x: int) -> bytes:
	return x.to_bytes()
    
def bytes_to_int(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, 'big')

def int_arr_to_bytes(m):
	return b''.join([x.to_bytes(1,'big') for x in m])

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

def tokenize(msg):
	return [msg[i:i+8] for i in range(len(msg)-8)]


def get_ecc_point():
	p = conn.recvline().split(b' ')
	return ECC.EccPoint(int(p[0],16),int(p[1],16))

def get_inter_rule(R):
	conn.recvline()
	conn.recvline()
	conn.recvline()

	msg = (hex(R.x)[2:]+' '+hex(R.y)[2:]).encode('utf-8')
	signiture = b64.b64encode(sig.sign(msg))
	conn.sendline(b'1')
	conn.sendline(msg)
	conn.sendline(signiture)
	return get_ecc_point()

def get_traffic():
	conn.recvline()
	conn.recvline()
	conn.recvline()

	conn.sendline(b'2')
	traffic = conn.recvline().split(b'|')
	c = int(traffic[0])
	traffic = b64.b64decode(traffic[1])
	traffic = [traffic[i:i+32] for i in range(0,len(traffic),32)]
	return c,traffic

def print_plain(p):
	for c in p:
		if c in printable:
			print(chr(c),end='')
		else:
			print('*',end='')
	print()


server = '127.0.0.1'
port = 5555
conn = remote(server,port)
x = conn.recvline() # welcome line
g=get_ecc_point()
print("[*] Got g:",g.x,g.y)
h=get_ecc_point()
print("[*] Got h:",h.x,h.y)


k_mb = bytes_to_int(get_random_bytes(32))


Rrg = g*k_mb
Rrh = h*k_mb

Irg = get_inter_rule(Rrg)
Irh = get_inter_rule(Rrh)


k_mb_inv = pow(k_mb,n-2,n)

Srg = Irg*k_mb_inv
Srh = Irh*k_mb_inv

def forge_encryption(ci,m):
	forged_encryption = Srg*bytes_to_int(H1(m))+Srh
	return H2(ci,int_to_bytes(forged_encryption.x))

c,Tokens = get_traffic()
print('[*] Got counter',c)
print('[*] Got',len(Tokens),'traffic tokens')


known_plaintext = b'Accept-Encoding:'[:8]


plaintext = [0]*(len(Tokens)+7)

found_index = -1
for i in range(len(Tokens)):
	Ti_forged = forge_encryption(c+i,known_plaintext)
	if Ti_forged == Tokens[i]:
		found_index = i
		plaintext[i:i+8] = known_plaintext

if found_index == -1:
	print("No tokens found. Increase known plaintext dictionary")
	exit()

print("[*] Found known_plaintext at",found_index)
print_plain(plaintext)
conn.close()

import time
print("Starting attack.")
time.sleep(3)


for i in range(found_index+1,len(Tokens)):
	found = False
	for x in printable:
		if forge_encryption(c+i,int_arr_to_bytes(plaintext[i:i+7]+[x])) == Tokens[i]:
			plaintext[i+7] = x
			found = True
			break
	if not found:
		print("Error at byte attack.")
		exit()

	os.system('clear')

	print_plain(plaintext) 


for i in range(found_index-1,-1,-1):
	found = False
	for x in printable:
		if forge_encryption(c+i,int_arr_to_bytes([x]+plaintext[i+1:i+8])) == Tokens[i]:
			plaintext[i] = x
			found = True
			break
	if not found:
		print("Error at reversed-byte attack.")
		exit()
		
	os.system('clear')
	print_plain(plaintext) 

