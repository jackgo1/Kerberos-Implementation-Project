import binascii
import datetime
import socket
import struct
import hashlib
import os
import msvcrt

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

current_directory = os.path.dirname(os.path.abspath(__file__))
file_name = 'me.info'
file_path = os.path.join(current_directory, file_name)

VERSION = 24
HEADER_FORMAT = 'BHI'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
client_id = ''

AUTH_SERVER_IP = '127.0.0.1'
MSG_SERVER_IP = '127.0.0.1'

AUTH_SERVER_PORT = 1234
MSG_SERVER_PORT = 1235

def main():

    read_srv_file()
    try:
        with open(file_path, 'r') as file:
            name = file.readline()
            global client_id
            client_id_hex = file.readline()
            client_id = binascii.unhexlify(client_id_hex)
    

    except FileNotFoundError:
        while (not sign_up()): 
            clear_screen()
            print('try again')
        

    except Exception as e:
        print(f'error: {e}')

    msg_server_dict = get_msg_servers()
    msg_server_id = select_msg_server(msg_server_dict)
    data = request_key(msg_server_id)

    key_sent = send_key(data, msg_server_dict[msg_server_id], msg_server_id)
    if (key_sent):
        chat(data['key'], msg_server_dict[msg_server_id])
    else:
        print('Error in sending key to message server.\nPlease try again.')
        

def get_msg_servers():
    s = connect_to_auth_server()
    code = 1026
    headers = struct.pack('16sBHI', client_id, VERSION, code, 0)
    s.sendall(headers)

    server_answer = b''

    while True:
        chunk = s.recv(1024)  # Adjust buffer size as needed
        if not chunk:
            break
        server_answer += chunk
    s.close()

    version, code, payload_size = struct.unpack(HEADER_FORMAT, server_answer[:HEADER_SIZE])
    payload = server_answer[HEADER_SIZE:]
    num_of_servers = payload_size//278
    servers_data = {}
    for i in range(num_of_servers):
        try:
            server_id, name, ip, port = struct.unpack('16s255s4sH', payload[i * 278:(i + 1) * 278])

            # Convert bytes to string and remove trailing spaces
            server_id = server_id.strip()
            name = name.rstrip(b'\x00').decode()
            ip = socket.inet_ntoa(ip)

            # Add the server data to the new dictionary
            servers_data[server_id] = {'name': name, 'ip': ip, 'port': port}

        except struct.error as e:
            print(f'Error unpacking data: {e}')
    
    return servers_data

def select_msg_server(servers):
    
    options = []
    reversed_dict = {}
    for server in servers:
        options.append(servers[server]['name'])
        reversed_dict[servers[server]['name']] = server
    
    selected_index = 0
    
    while True:
        print_menu(options, selected_index)

        key = msvcrt.getch()

        if key == b'\xe0':  # Arrow keys start with b'\xe0'
            key = msvcrt.getch()
            if key == b'H' and selected_index > 0:  # Up arrow
                selected_index -= 1
            elif key == b'P' and selected_index < len(options) - 1:  # Down arrow
                selected_index += 1
        elif key == b'\r':  # Enter key
            print("You selected:", options[selected_index])
            return reversed_dict[options[selected_index]]
            break

def print_menu(options, selected_index):
    clear_screen()
    for index, option in enumerate(options):
        if index == selected_index:
            print("[x]", option)
        else:
            print("[ ]", option)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def send_key(data, msg_server, msg_server_id):
    global client_id

    s = connect_to_msg_server(msg_server['ip'], msg_server['port'])
    authenticator = create_authenticator(data['key'], msg_server_id)

    payload_format = f'{len(authenticator)}s{len(data['ticket'])}s'
    payload = struct.pack(payload_format, authenticator, data['ticket'])

    headers = struct.pack('16sBHI', client_id, VERSION, 1028, struct.calcsize(payload_format))
    headers_size = struct.calcsize('16sBHI')
    msg = struct.pack(f'{headers_size}s{struct.calcsize(payload_format)}s', headers, payload)
    s.sendall(msg)
    server_answer = s.recv(1024)
    s.close()

    version, code, payload_size = struct.unpack(HEADER_FORMAT, server_answer[:HEADER_SIZE])
    if code == 1604:
        return True
    return False




def create_authenticator(key, msg_server_id):
    global client_id
    auth_headers = '16s16s16s16s16s'
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S").encode()
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_version = cipher.encrypt(pad(str(VERSION).encode('utf-8'), AES.block_size))
    encrypted_client_id = cipher.encrypt(client_id)
    encrypted_server_id = cipher.encrypt(msg_server_id)
    encrypted_creation_time = cipher.encrypt(pad(current_time, AES.block_size))
    iv = cipher.iv
    authenticator = struct.pack(auth_headers, iv, encrypted_version, encrypted_client_id, encrypted_server_id, encrypted_creation_time)
    
    return authenticator

def connect_to_msg_server(ip, port):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        s.connect((ip, port))
        return s

    except Exception as e:
        print(f"An error occurred: {e}")
    
    return None

    print("connect_to_msg_server")

def chat(key, msg_server):
    global client_id
    clear_screen()
    s = connect_to_msg_server(msg_server['ip'], msg_server['port'])
    code = 1605
    while(code == 1605):
        cipher = AES.new(key, AES.MODE_CBC)
        msg = input("enter youe message: ")
        msg = msg.encode('utf-8')

        encrypted_msg = cipher.encrypt(pad(msg, AES.block_size))

        iv = cipher.iv
        payload_format = f'I16s{len(encrypted_msg)}s'
        payload = struct.pack(payload_format, len(encrypted_msg), iv, encrypted_msg)
        headers = struct.pack('16sBHI', client_id, VERSION, 1029, struct.calcsize(payload_format))
        data_format = f'{struct.calcsize('16sBHI')}s{struct.calcsize(payload_format)}s'
        data = struct.pack(data_format, headers, payload)

        s.sendall(data)
        
        server_answer = s.recv(1024)
        version, code, payload_size = struct.unpack(HEADER_FORMAT, server_answer)


    s.close()



def connect_to_auth_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        s.connect((AUTH_SERVER_IP, AUTH_SERVER_PORT))
        return s

    except Exception as e:
        print(f"An error occurred: {e}")
    
    return None

def create_file():
    print('creating file')
    f = open(file_path, 'w')
    f.close()

def sign_up():
    
    s = connect_to_auth_server()
    
    if(s == None):
        print('did now manage to connect to server')
        return None

    code = 1024  # Registration code

    name = valid_input('Enter a name: ')
    password = valid_input("Enter password: ")

    password_hash = hashlib.sha256(password.encode('utf-8')).digest()
    name_bytes = name.encode('utf-8')  # Convert to bytes
    rand_client_id = get_random_bytes(16)

    payload_size = 255*2

    data = struct.pack(f'16sBHI255s255s', rand_client_id, VERSION, code, payload_size, name_bytes, password_hash)

    s.sendall(data)
    s.listen
    server_answer = s.recv(1024)
    s.close()

    version, code, payload_size = struct.unpack(HEADER_FORMAT, server_answer[:HEADER_SIZE])

    if(code == 1600):
        create_file()
        global client_id
        client_id = struct.unpack('16s', server_answer[HEADER_SIZE:])[0]
        client_id_hex = binascii.hexlify(client_id).decode()
        print('success')

        try:
            with open(file_path, 'w') as client_info:
                client_info.write(name)
                client_info.write('\n')
                client_info.write(client_id_hex)
                client_info.close()
                return True
            
        except Exception as e:
            print(e)
    else:
        print('fail')
    
    return False

def request_key(mag_server_id):
    global client_id
    print('requesting key')

    s = connect_to_auth_server()
    if(s == None):
        print('did not manage to connect to server')
        return None

    code = 1027
    nonce = get_random_bytes(8)

    data = struct.pack(f'16sBHI16s8s', client_id, VERSION, code, 24, mag_server_id, nonce)
    s.sendall(data)
    s.listen
    server_answer = s.recv(1024)
    s.close()

    encrypted_key_headers = '16s16s32s'
    ticket_headers = 'B16s16s8s16s32s32s'
    data_headers = f'16s{struct.calcsize(encrypted_key_headers)}s{struct.calcsize(ticket_headers)}s'
    client_id_returned , encrypted_key, ticket = struct.unpack(data_headers, server_answer)

    iv, encrypted_nonce, encrypted_aes_key = struct.unpack(encrypted_key_headers, encrypted_key)
    
    while(True):
        password = input("Enter password: ")
        password_hash = hashlib.sha256(password.encode('utf-8')).digest()

        cipher = AES.new(password_hash, AES.MODE_CBC, iv)
        decrypted_nonce = cipher.decrypt(encrypted_nonce)
        try:
            decrypted_nonce = unpad(decrypted_nonce, AES.block_size)
        except ValueError as ve:
            continue
        except Exception as e:
            print(e)

        if(nonce == decrypted_nonce):
            break
    
    decrypted_aes_key = cipher.decrypt(encrypted_aes_key)
    try:
        decrypted_aes_key = unpad(decrypted_aes_key, AES.block_size)
    except ValueError as ve:
        pass
    except Exception as e:
        print(e)
    return {'ticket': ticket, 'key': decrypted_aes_key}

def valid_input(str):
    
    user_input = input(str).strip()
    while (len(user_input) > 255):
        user_input = input("please enter less then 255 characters").strip()
    return user_input

def read_srv_file():
    global AUTH_SERVER_IP
    global MSG_SERVER_IP
    global AUTH_SERVER_PORT
    global MSG_SERVER_PORT

    srv_path = os.path.join(current_directory, 'srv.info')
    
    try:
        with open(srv_path, 'r') as file:
            lines = file.readlines()
            AUTH_SERVER_IP, AUTH_SERVER_PORT = lines[0].strip().split(':')
            MSG_SERVER_IP, MSG_SERVER_PORT = lines[1].strip().split(':')

            # Convert port numbers to integers
            AUTH_SERVER_PORT = int(AUTH_SERVER_PORT)
            MSG_SERVER_PORT = int(MSG_SERVER_PORT)

    except FileNotFoundError:
        print('File srv.info not found. Using default values.')

    except Exception as e:
        print(f'Error: {e}')



if __name__ == "__main__":
    main()