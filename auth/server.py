import binascii
import socket
import struct
import datetime
import os
from base64 import b64decode, b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import threading


VERSION = 24
DEFULT_PORT = 1256
PORT_FILE = 'port.info'
MSG_SERVER_FILE = 'msg.info'
CLIENTS_FILE = 'clients'
current_directory = os.path.dirname(os.path.abspath(__file__))
HEADER_FORMAT = '16sBHI'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
clients_name_list = []
clients_dict = {}

servers_name_list = []
servers_dict = {}

def main():

    load_clients_dict()
    load_servers_dict()
    load_clients_name_list()
    print(clients_name_list)
    port = read_server_port()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(('127.0.0.1', port))
        server_socket.listen()
        print(f"Server listening on port {port}...")
        
        while True:

            client_socket, addr = server_socket.accept()
            print(f"Connection from {addr}")
            thread = threading.Thread(target=handle_client, args=(client_socket,))
            thread.start()

def handle_client(client_socket):
    
    try:
        client_data = client_socket.recv(1024)
        # Process client data...
    except Exception as e:
        print(f"An error occurred while handling client: {e}")
        return

    client_id, version, code, payload_size = struct.unpack(HEADER_FORMAT, client_data[:HEADER_SIZE])
    print('handeling id: ', client_id)
    if(version != VERSION):
        #TODO check if works
        print('error')

    elif(len(client_data[HEADER_SIZE:]) != payload_size):
        print(f"len of client_data[HEADER_SIZE:] = {len(client_data[HEADER_SIZE:])} ")
        print(f"len of payload_size = {payload_size}")
        print('not the same size')
        #TODO check if works
        print('error')

    else:
        match code:
            case 1024:
                user_sign_up(client_data[HEADER_SIZE:], client_socket)
            case 1025:
                server_sign_up(client_data[HEADER_SIZE:], client_socket)
            case 1026:
                get_servers(client_socket)
            case 1027:
                get_key(client_id, client_data[HEADER_SIZE:], client_socket)

    client_socket.close()

def user_sign_up(payload, client_socket):
    print('sign up')

    payload_format = '255s255s'
    name, password_hash = struct.unpack(payload_format, payload)
    name = name.rstrip(b'\x00').decode('utf-8')
    password_hash = password_hash.rstrip(b'\x00')
    print('11111111\n',password_hash)
    if (name not in clients_name_list):
        print('\n1\n')
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        id = get_random_bytes(16)
        while(id in clients_dict):
            id = get_random_bytes(16)
        
        id_hex = binascii.hexlify(id).decode()
        file_lock = threading.Lock() 
        file_path = os.path.join(current_directory, CLIENTS_FILE)
        try:
            with file_lock:
                print('\n2\n')
                with open(file_path, 'a') as clients_file:
                    clients_file.write(f'{id_hex}:{name}:{password_hash}:{current_time}\n')
        except Exception as e:
            print(e)
        clients_dict[id] =  password_hash
        clients_name_list.append(name)
        response_code = 1600
        data = struct.pack(f'BHI16s', VERSION, response_code, 16, id)
        client_socket.sendall(data)
        return


    else:
        print('1601')
    response_code = 1601
    data = struct.pack(f'BHI', VERSION, response_code, 0)
    client_socket.sendall(data)
    

def server_sign_up(payload, socket):
    ip, port = socket.getpeername()
    payload_format = '255s32s'
    name, aes_key = struct.unpack(payload_format, payload)
    name = name.rstrip(b'\x00').decode('utf-8')
    aes_key = aes_key.rstrip(b'\x00')
    aes_key = b64encode(aes_key).decode()
    file_path = os.path.join(current_directory, MSG_SERVER_FILE)

    try:
        file_lock = threading.Lock() 
        id = get_random_bytes(16)
        while(id in servers_dict):
            id = get_random_bytes(16)
        id_hex = binascii.hexlify(id).decode()
        with file_lock:           
            with open(file_path, 'a') as servers_file:
                servers_file.write(f'{ip}:{port}\n{name}\n{id_hex}\n{aes_key}\n')
                servers_dict[id] = {'name': name, 'ip': ip, 'port': port, 'key': aes_key}
        response_code = 1600
        data = struct.pack(f'BHI16s', VERSION, response_code, 16, id)
        socket.sendall(data)
    except Exception as e:
        print(e)



def get_key(client_id, payload, client_socket):
    
    global servers_dict, clients_dict
    payload_format = '16s8s'
    msg_server_id, nonce = struct.unpack(payload_format, payload)

    print("client dict: \n", clients_dict)
    msg_server_key = b64decode(servers_dict[msg_server_id]['key'])
    password_hash = clients_dict[client_id]
    client_key = password_hash
    code = 1027

    encrypted_key_headers = '16s16s32s'

    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S").encode()
    expiration_time = datetime.datetime.now() + datetime.timedelta(days=1)
    expiration_time = expiration_time.strftime("%Y-%m-%d %H:%M:%S").encode()
    aes_key = get_random_bytes(32)

    client_cipher = AES.new(client_key, AES.MODE_CBC)
    encrypted_nonce = client_cipher.encrypt(pad(nonce, AES.block_size))
    user_encrypted_key = client_cipher.encrypt(aes_key)
    client_iv = client_cipher.iv

    msg_cipher = AES.new(msg_server_key, AES.MODE_CBC)
    msg_encrypted_key = msg_cipher.encrypt(aes_key)
    encrypted_expiration_time = msg_cipher.encrypt(pad(expiration_time, AES.block_size))
    ticket_iv = msg_cipher.iv

    encrypted_key = struct.pack(encrypted_key_headers, client_iv, encrypted_nonce, user_encrypted_key)
    

    ticket_headers = f'B16s16s8s16s{len(msg_encrypted_key)}s{len(encrypted_expiration_time)}s'
    print('ticket_headers: ', ticket_headers)
    ticket = struct.pack(ticket_headers, 24, client_id, msg_server_id, current_time, ticket_iv, msg_encrypted_key, encrypted_expiration_time)
    
    data_headers = f'16s{struct.calcsize(encrypted_key_headers)}s{struct.calcsize(ticket_headers)}s'
    data = struct.pack(data_headers, client_id ,encrypted_key, ticket)
    print("data key = \n",data,'\n')
    client_socket.sendall(data)

    return


def get_servers(client_socket):
    paload = b''
    for server in servers_dict:
        id = server
        ip = socket.inet_aton(servers_dict[server]['ip'])
        port = servers_dict[server]['port']
        name = servers_dict[server]['name'].encode('utf-8')
        temp = struct.pack('16s255s4sH', id, name, ip, port)
        paload += temp

    
    answer_format = f'BHI{len(paload)}s'
    answer = struct.pack(answer_format, VERSION, 1602, len(paload), paload)
    
    client_socket.sendall(answer)
    

def load_clients_name_list():
    global clients_name_list
    file_path = os.path.join(current_directory, CLIENTS_FILE)
    try:
        with open(file_path, 'r') as clients_file:
            clients = clients_file.readlines()
            for client in clients:
                name = client.split(':')[1].strip()
                clients_name_list.append(name)
            clients_file.close
    except FileNotFoundError:
        with open(CLIENTS_FILE, 'w') as clients_file:
            clients_file.close


    except Exception as e:
        print (e)


def load_clients_dict():
    global clients_dict
    file_path = os.path.join(current_directory, CLIENTS_FILE)
    try:
        with open(file_path, 'r') as clients_file:
            clients = clients_file.readlines()
            for client in clients:
                client_data = client.split(':')
                client_id = client_data[0].strip()
                client_id = binascii.unhexlify(client_id)
                password_hash = eval(bytes(client_data[2].strip().encode()))
                clients_dict[client_id] = password_hash
    except FileNotFoundError:
        with open(CLIENTS_FILE, 'w') as clients_file:
            clients_file.close()
    except Exception as e:
        print(e)
    print('client dict = \n', clients_dict)


def load_servers_dict():

    global servers_dict
    file_path = os.path.join(current_directory, MSG_SERVER_FILE)
    try:
        with open(file_path, 'r') as servers_file:
            lines = servers_file.readlines()
            for i in range(0, len(lines), 4):
                # Extract data for each server
                ip_port = lines[i].strip().split(':')
                ip = ip_port[0]
                port = int(ip_port[1])
                name = lines[i+1].strip()
                server_id = lines[i+2].strip()
                key = lines[i+3].strip()
                server_id = binascii.unhexlify(server_id)
                servers_dict[server_id] = {'name': name, 'ip': ip, 'port': port, 'key': key}


    except FileNotFoundError:
        with open(CLIENTS_FILE, 'w') as clients_file:
            servers_file.close()
    except Exception as e:
        print(e)


def read_server_port():
    try:
        port_file_path = os.path.join(os.path.dirname(__file__), 'port.info')
        with open(port_file_path, 'r') as file:
            port = int(file.read().strip())
            print(f"Using port {port} from {PORT_FILE} file.")
            return port
    except Exception as e:
        print(f"Warning: {PORT_FILE} file not found or invalid. Using default port {DEFULT_PORT}. Error: {e}")
        return DEFULT_PORT

    
def load_message_server_details():
    try:
        file_path = os.path.join(os.path.dirname(__file__), 'msg.info')
        with open(file_path, 'r') as file:
            lines = file.readlines()
            if len(lines) < 4:
                raise ValueError("Invalid msg.info format")
            ip_address, port = lines[0].strip().split(':')
            server_details = {
                'ip_address': ip_address,
                'port': int(port),
                'server_name': lines[1].strip(),
                'unique_identifier': lines[2].strip(),
                'symmetric_key_base64': lines[3].strip()
            }

            # Printing the loaded message server details
            print("Loaded message server details from msg.info:")
            # for key, value in server_details.items():
            #     print(f"{key}: {value}")

            return server_details
    
    except FileNotFoundError:
        print("msg.info file not found.")
        return None
    except ValueError as e:
        print(f"Error reading msg.info file: {e}")
        return None
    except Exception as e:
        print(f"Failed to load msg.info: {e}")
        return None






if __name__ == "__main__":
    main()