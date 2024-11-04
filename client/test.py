import binascii
import hashlib
from Crypto.Random import get_random_bytes
from base64 import b64decode, b64encode


# client_id = 'ceefb88328a3da579d869780d1f522a0'
# # client_id_hex = binascii.hexlify(client_id).decode()
# original_id = binascii.unhexlify(client_id)
# #client_id_b64 = b64encode(client_id).decode()

id = b'PV8I\x90\x11\xe3\x8et\xbfG\x0c\x90\x8e\x82`'
print(id)

# print(client_id_b64)
# client_id = 0
# original = b64decode(client_id_b64)
# print(original)

password = '1234'

password_hash = hashlib.sha256(password.encode('utf-8')).digest()
#password_hash_bytes = password_hash.encode('utf-8')

print(password_hash)
#print(password_hash_bytes)