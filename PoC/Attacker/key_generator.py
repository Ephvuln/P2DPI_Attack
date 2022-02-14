import ecdsa

# SECP256k1 is the Bitcoin elliptic curve
sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1) 
vk = sk.get_verifying_key()
with open('key.pub','wb') as f:
	f.write(vk.to_pem())

with open('key.priv','wb') as f:
	f.write(sk.to_pem())
#sig = sk.sign(b"message")
#vk.verify(sig, b"message") # True