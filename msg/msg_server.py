import binascii
import socket
import struct
import threading
from hashlib import sha256
import datetime
import os
from base64 import b64decode, b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

current_directory = os.path.dirname(os.path.abspath(__file__))

AUTH_SERVER_IP = '127.0.0.1'
AUTH_SERVER_PORT = 1234
IP = '127.0.0.1'
PORT = 1235
NAME = ''
VERSION = 24
SERVER_ID = 0
AES_KEY = 0
clients_dict = {}

def main():

    srv_file_lines = read_srv_file() 
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((IP, PORT))
        
        if (len(srv_file_lines) == 3):
            sign_up(server_socket)
            # while(not sign_up()):
            #     print('please try signing up again')
        else:
            load_server_details(srv_file_lines);
        
        server_socket.listen()
        while True:

            client_socket, addr = server_socket.accept()
            thread = threading.Thread(target=handle_client, args=(client_socket,))
            thread.start()

def handle_client(client_socket):
    try:
        client_data = client_socket.recv(1024) 
        header_format = '16sBHI'
        header_size = struct.calcsize(header_format)
        client_id, version, code, payload_size = struct.unpack(header_format, client_data[:header_size])
        if(version != VERSION):
            #TODO check if works
            print('error')

        elif(len(client_data[header_size:]) != payload_size):
            print(f"len of client_data[HEADER_SIZE:] = {len(client_data[header_size:])} ")
            print(f"len of payload_size = {payload_size}")
            print('not the same size')
            #TODO check if works 

        else:
            match code:
                case 1028:
                    get_aes_key(client_data[header_size:], client_socket)
                case 1029:
                    get_message(client_data[header_size:], client_socket, client_id)
    except ConnectionResetError:
        pass
    except Exception as e:
        pass
    
def get_message(data, socket, client_id):
    global clients_dict
    if client_id not in clients_dict:
        send_error_to_client(socket)
        return
    
    key = clients_dict[client_id]
    msg_format = 'I16s'
    msg_size, iv = struct.unpack(msg_format, data[:struct.calcsize(msg_format)])
    encrypted_msg = struct.unpack(f'{msg_size}s', data[struct.calcsize(msg_format):])[0]  # Access the first element of the tuple
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    msg = cipher.decrypt(encrypted_msg)
    
    try:    
        msg = unpad(msg, AES.block_size)
        msg = msg.decode('utf-8')
    except Exception as e:
        print('no need padd')

    
    print(msg)
    data = struct.pack(f'BHI', VERSION, 1605, 0)
    socket.sendall(data)
    handle_client(socket)

def get_aes_key(data, socket):

    auth_headers = '16s16s16s16s16s'
    ticket_headers = 'B16s16s8s16s32s32s'
    auth_size = struct.calcsize(auth_headers)
    ticket_size = struct.calcsize(ticket_headers)
    data_format = f'{auth_size}s{ticket_size}s'
    auth, ticket = struct.unpack(data_format, data)
    ticket_dict = dycrypt_ticket(ticket, ticket_headers)
    auth_dict = dycrypt_auth(auth, auth_headers, ticket_dict['key'])

    if auth_dict['client id'] != ticket_dict['client id']:
        #print('not the same client id')
        send_error_to_client(socket)
        return
    
    if not (auth_dict['version'] == ticket_dict['version'] == VERSION):
        #print('not the same version')
        send_error_to_client(socket)
        return
        
    if not (auth_dict['msg server id'] == ticket_dict['msg server id'] == SERVER_ID) :
        #print('not the same server id')
        send_error_to_client(socket)
        return
    expiration_time_bytes = ticket_dict['expiration time']
    expiration_time_str = expiration_time_bytes.decode('utf-8')  # Convert bytes to string

    # Convert expiration time string to datetime object
    expiration_time = datetime.datetime.strptime(expiration_time_str, "%Y-%m-%d %H:%M:%S")

    if not (datetime.datetime.now() < expiration_time) :
        #print(f'ticket expired.')
        send_error_to_client(socket)
        return
    
    
    global clients_dict
    clients_dict[ticket_dict['client id']] = ticket_dict['key']
    data = struct.pack(f'BHI', VERSION, 1604, 0)
    socket.sendall(data)
    socket.close()

    return
    
        
def send_error_to_client(socket):
    data = struct.pack(f'BHI', VERSION, 1609, 0)
    socket.sendall(data)
    socket.close()

def dycrypt_ticket(ticket, headers):

    version, client_id, msg_server_id, current_time, ticket_iv, msg_encrypted_key, expiration_time = struct.unpack(headers, ticket)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, ticket_iv)

    ticket_dict  = {
        'version': version,
        'client id': client_id,
        'msg server id': msg_server_id,
        'current time': current_time,
        'ticket iv': ticket_iv,
        'key': cipher.decrypt(msg_encrypted_key),
        'expiration time': unpad(cipher.decrypt(expiration_time), AES.block_size)
        }
    return ticket_dict
    
    
def dycrypt_auth(auth, headers, key):
    auth_iv, version, client_id, msg_server_id, creation_time = struct.unpack(headers, auth)
    cipher = AES.new(key, AES.MODE_CBC, auth_iv)

    auth_dict = {
        'version': int(unpad(cipher.decrypt(version), AES.block_size)),
        'client id': cipher.decrypt(client_id),
        'msg server id': cipher.decrypt(msg_server_id),
        'creation time': cipher.decrypt(creation_time)
    }
    return auth_dict


def sign_up():
    s = connect_to_auth_server()
    
    if(s == None):
        #print('did not manage to connect to server')
        return None

    code = 1025  # MSG Server registration code
    aes_key = get_random_bytes(32)
    name_bytes = NAME.encode('utf-8')  # Convert to bytes
    rand_msg_id = get_random_bytes(16)
    payload_size = 255+32

    data = struct.pack(f'16sBHI255s32s', rand_msg_id, VERSION, code, payload_size, name_bytes, aes_key)

    s.sendall(data)
    s.listen
    server_answer = s.recv(1024)
    s.close()
    header_format = 'BHI'
    header_size = struct.calcsize(header_format)
    version, code, payload_size = struct.unpack(header_format, server_answer[:header_size])

    if(code == 1600):
        global SERVER_ID
        global AES_KEY
        AES_KEY = aes_key
        SERVER_ID = struct.unpack('16s', server_answer[header_size:])[0]
        server_id_hex = binascii.hexlify(SERVER_ID).decode()
        file_path = os.path.join(current_directory, 'msg.info')

        try:
            with open(file_path, 'a') as msg_info:
                msg_info.write(f'\n{server_id_hex}\n')
                msg_info.write(b64encode(aes_key).decode())
                msg_info.close()
                return True
            
        except Exception as e:
            print(e)
    else:
        print('fail')
    
    return False

def read_srv_file():
    global AUTH_SERVER_IP, AUTH_SERVER_PORT, NAME, IP, PORT

    msg_path = os.path.join(current_directory, 'msg.info')
    
    try:
        with open(msg_path, 'r') as file:
            lines = file.readlines()
            AUTH_SERVER_IP, AUTH_SERVER_PORT = lines[0].strip().split(':')
            IP, PORT = lines[1].strip().split(':')

            # Convert port numbers to integers
            AUTH_SERVER_PORT = int(AUTH_SERVER_PORT)
            PORT = int(PORT)
            NAME = lines[2].strip()
        return lines
    except FileNotFoundError:
        print('File srv.info not found. Using default values.')

    except Exception as e:
        print(f'Error: {e}')

def connect_to_auth_server(s): 

    try:
        s.connect((AUTH_SERVER_IP, AUTH_SERVER_PORT))
        return s

    except Exception as e:
        print(f"An error occurred: {e}")
    
    return None

def load_server_details(list):
    global SERVER_ID
    global AES_KEY
    SERVER_ID = binascii.unhexlify(list[3].strip())
    AES_KEY = b64decode(list[4].strip())

def valid_input(str):
    
    user_input = input(str).strip()
    while (len(user_input) > 255):
        user_input = input("please enter less then 255 characters").strip()
    return user_input




    

if __name__ == "__main__":
    main()