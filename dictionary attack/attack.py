import hashlib
import os
import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
  
 
user_sent_request =  b'\xb8\xbd\x94\xec\x10\xc8\xf5\xa8(\xda\xfe& \xa3W\xa3\x18\x00\x03\x04\x18\x00\x00\x00\xce\xef\xb8\x83(\xa3\xdaW\x9d\x86\x97\x80\xd1\xf5"\xa0\xa8\xae\x0f\x81\xe6t$&'

server_answer = b'\xb8\xbd\x94\xec\x10\xc8\xf5\xa8(\xda\xfe& \xa3W\xa3\xc2/\xdf\xd5\x08\xd2\xf5 \x83\x914\x1c\x85\xb4r\x84SP\xech\x15\xbe\xe0//\x1c\x9c\xba\x8f^\xaa\xbf\x95\xdd\xe6\xc8\x18B\x1cw\x1c\x83\x13\x0e\x14h&{\x1b4\xd9%@\xb7\x9f\x191\xa8e\xa8\x93\xb6\xc1\xc7\x18\xb8\xbd\x94\xec\x10\xc8\xf5\xa8(\xda\xfe& \xa3W\xa3\xce\xef\xb8\x83(\xa3\xdaW\x9d\x86\x97\x80\xd1\xf5"\xa02024-03-v|\x9a\xd1\xb7\xb4(\x04\x89\xae5oN\x1d|\x0bJ\x8d\xe8z\xf7\xd1N\xa7\xda\x028$\xa4\x96I\x963\x02\x82\x10#\xb6\xe1N\xfa\xce\x19\x04R\xa1\x12\x9e\xa6\x91.\x85>b\x97\x19\x87\x81H\xee\xcb\xe1;\x8a$q\x1d\xa0\x19\x06\xfeqx\xba.\xb9\x97m2\xc5'

header_format = '16sBHI'
heades_size = struct.calcsize(header_format)
client_id, version, code, payload_size = struct.unpack(header_format, user_sent_request[:heades_size])

payload_format = '16s8s'
msg_server_id, nonce = struct.unpack(payload_format, user_sent_request[heades_size:])

print(nonce)

encrypted_key_headers = '16s16s32s'
ticket_headers = 'B16s16s8s16s32s32s'
data_headers = f'16s{struct.calcsize(encrypted_key_headers)}s{struct.calcsize(ticket_headers)}s'
client_id_returned , encrypted_key, ticket = struct.unpack(data_headers, server_answer)

iv, encrypted_nonce, encrypted_aes_key = struct.unpack(encrypted_key_headers, encrypted_key)

print(encrypted_nonce)

current_directory = os.path.dirname(os.path.abspath(__file__))
passwords_path = os.path.join(current_directory, 'passwords.txt')


with open(passwords_path, 'r') as file:
    passwords = file.readlines()
    for p in passwords:
        password_hash = hashlib.sha256(p.strip().encode('utf-8')).digest()
        cipher = AES.new(password_hash, AES.MODE_CBC, iv)
        decrypted_nonce = cipher.decrypt(encrypted_nonce)
        try:
            decrypted_nonce = unpad(decrypted_nonce, AES.block_size)
        except ValueError as ve:
            continue
        if decrypted_nonce == nonce:
            print('password is: ', p)
            break

