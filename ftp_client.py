import socket
import ssl
import os
import subprocess as sp
import sys
import time
from tqdm import tqdm

class ClientSocket:
    def __init__(self, host, port=21):
        self.control_socket = None
        self.is_passive = True
        self.host = host
        self.port = port
        self.context = None
        self.transfer_mode = 'I'

    def recv_response(self):
        return self.control_socket.recv(4096).decode()

    def send_command(self, cmd):
        if not cmd.endswith("\r\n"):
            cmd += "\r\n"
        self.control_socket.send(cmd.encode())

    def connect(self):
        try:
            self.control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.control_socket.settimeout(10)
            self.control_socket.connect((self.host, self.port))
            response = self.recv_response()
            print(response)
            return True
        except Exception as e:
            print(f"Error connection: {e}")
            return False

    def login(self, username, password):
        try:
            self.send_command("AUTH TLS")
            response = self.recv_response()
            print(response)
            if response.startswith("234"):
                self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                self.context.check_hostname = False
                self.context.verify_mode = ssl.CERT_NONE
                self.control_socket = self.context.wrap_socket(self.control_socket, server_hostname=self.host)
            self.send_command(f"USER {username}")
            response = self.recv_response()
            print(response)
            self.send_command(f"PASS {password}")
            response = self.recv_response()
            print(response)
            if response.startswith("230"):
                self.send_command("PROT P")
                response = self.recv_response()
                print(response)
                self.set_transfer_mode('I')
                return True
            return False
        except Exception as e:
            print(f"Error login: {e}")
            return False

    def passive_mode(self):
        print("Setting Passive mode")
        self.send_command("PASV")
        response = self.recv_response()
        print(response)
        res = response.split(' ')
        if not res:
            raise Exception("Unable to analyze PASV response")
        res[-1] = res[-1][:-3]
        data_channel = str(res[-1]).split(',')
        data_channel[0] = data_channel[0][1:]
        data_host = f"{data_channel[0]}.{data_channel[1]}.{data_channel[2]}.{data_channel[3]}"
        data_port = int(data_channel[-2]) * 256 + int(data_channel[-1])
        print(f"Connecting to Data Channel at {data_host}:{data_port}")
        data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data_socket.connect((data_host, data_port))
        return data_socket

    def active_mode(self):
        print("Setting Active mode")
        data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data_socket.bind(("", 10806))
        data_socket.listen(1)
        ip, port = self.control_socket.getsockname()
        h1, h2, h3, h4 = map(int, ip.split('.'))
        p1 = 10806 // 256
        p2 = 10806 % 256
        command = f"PORT {h1},{h2},{h3},{h4},{p1},{p2}"
        self.send_command(command)
        response = self.recv_response()
        print(response)
        if not response.startswith("200"):
            raise Exception("Server refused PORT command")
        print(f"Client is listening for data connection at {ip}:10806")
        return data_socket

    def get_data_socket(self, cmd):
        listen_socket = None
        data_socket = None
        if self.is_passive:
            data_socket = self.passive_mode()
        else:
            listen_socket = self.active_mode()
        self.send_command(cmd)
        if not self.is_passive:
            print("Waiting for server to connect")
            data_socket, adr = listen_socket.accept()
            print("Connection completed")
        return data_socket, listen_socket

    def list_files(self):
        listen_socket = None
        data_socket, listen_socket = self.get_data_socket("LIST")
        data_socket = self.context.wrap_socket(data_socket, session=self.control_socket.session)
        response = self.recv_response()
        print(response)
        if not response.startswith("150"):
            data_socket.close()
            return
        folder_list = ""
        while True:
            data = data_socket.recv(4096).decode()
            if not data:
                break
            folder_list += data
        print("\n----List of files----")
        print(folder_list)
        print("----------------------")
        data_socket.close()
        if listen_socket:
            listen_socket.close()
        response = self.recv_response()
        print(response)

    def change_directory_server(self, directory):
        print(f"Change directory on server '{directory}'")
        self.send_command(f"CWD {directory}")
        response = self.recv_response()
        print(response)

    def change_directory_local(self, directory):
        try:
            os.chdir(directory)
            print(f"Changed local directory to: {os.getcwd()}")
        except FileNotFoundError:
            print(f"Local directory '{directory}' is not available")
        except Exception as e:
            print(f"Error when changing local directory: {e}")

    def print_current_server_directory(self):
        self.send_command("PWD")
        response = self.recv_response()
        print(response)

    def make_directory(self, directory_name):
        print(f"Creating directory {directory_name}")
        self.send_command(f"MKD {directory_name}")
        response = self.recv_response()
        print(response)

    def remove_directory(self, directory_name):
        print(f"Removing directory {directory_name}")
        self.send_command(f"RMD {directory_name}")
        response = self.recv_response()
        print(response)

    def delete_file(self, file_name):
        print(f"Deleting file {file_name}")
        self.send_command(f"DELE {file_name}")
        response = self.recv_response()
        print(response)

    def rename_file(self, original_name, new_name):
        print(f"Change file name from {original_name} to {new_name}")
        self.send_command(f"RNFR {original_name}")
        response = self.recv_response()
        if response.startswith("350"):
            self.send_command(f"RNTO {new_name}")
            response = self.recv_response()
            print(response)
        else:
            print("Error: Server is nor ready for changing name")

    def get_file_size(self, filename):
        try:
            self.send_command(f"SIZE {filename}")
            response = self.recv_response()
            if response.startswith("213"):
                return int(response.split(" ")[1])
            return -1
        except Exception:
            return -1

    def scan_file_with_ClamAVAgent(self, filename):
        print(f"Scanning {filename} with ClamAVAgent")
        clamav_host = "127.0.0.1"
        clamav_port = 15116
        agent_process = None
        try:
            cmd = [sys.executable, "clamav_agent.py"]
            agent_process = sp.Popen(cmd, text=True)
            time.sleep(3)
            agent_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            filesize = os.path.getsize(filename)
            filesize_mb = os.path.getsize(filename) / (1024 * 1024)
            agent_socket.settimeout(45 + filesize_mb * 4)
            agent_socket.connect((clamav_host, clamav_port))
            agent_socket.send(f"{filename}<SEPARATOR>{filesize}".encode())
            with open(filename, "rb") as file, tqdm(
                total=filesize,
                unit='B',
                unit_scale=1024,
                desc="Uploading file to ClamAV Agent"
            ) as progress:
                while True:
                    data = file.read(4096)
                    if not data:
                        break
                    agent_socket.sendall(data)
                    progress.update(len(data))
            result = agent_socket.recv(4096).decode()
            agent_socket.close()
            if result == "CLEAN":
                return True
            else:
                return False
        except Exception as e:
            print(f"Unexpected error with agent: {e}")
            return False
        finally:
            if agent_process:
                agent_process.terminate()

    "Cần thêm trường hợp xử lý file bị trùng (STOU)"
    def put_file(self, local_filename, server_filename = None):
        if not os.path.exists(local_filename):
            print(f"File {local_filename} does not exist")
            return
        if not self.scan_file_with_ClamAVAgent(local_filename):
            print("This file is not safe")
            return
        if not server_filename:
            server_filename = os.path.basename(local_filename)
        listen_socket = None
        try:
            data_socket, listen_socket = self.get_data_socket(f"STOR {server_filename}")
            data_socket = self.context.wrap_socket(data_socket, session=self.control_socket.session)
            response = self.recv_response()
            print(response)
            if not response.startswith("150"):
                data_socket.close()
                if listen_socket:
                    listen_socket.close()
                return
            with open(local_filename, 'rb') as file, tqdm(
                total=os.path.getsize(local_filename),
                unit='B',
                unit_scale=1024,
                desc="Uploading to server"
            ) as progress:
                while True:
                    data = file.read(4096)
                    if not data:
                        break
                    data_socket.sendall(data)
                    progress.update(len(data))
                data_socket.close()
                if listen_socket:
                    listen_socket.close()
                response = self.recv_response()
                print(response)
        except Exception as e:
            print(f"Error when putting file: {e}")
            if listen_socket:
                listen_socket.close()

    def down_file(self, server_filename, local_filename = None):
        if not local_filename:
            local_filename = server_filename
        listen_socket = None
        try:
            filesize = self.get_file_size(server_filename)
            data_socket, listen_socket = self.get_data_socket(f"RETR {server_filename}")
            data_socket = self.context.wrap_socket(data_socket, session=self.control_socket.session)
            response = self.recv_response()
            print(response)
            if not response.startswith("150"):
                data_socket.close()
                if listen_socket:
                    listen_socket.close()
                return
            with open(local_filename, 'wb') as file, tqdm(
                total=filesize if filesize != -1 else None,
                unit='B',
                unit_scale=1024,
                desc="Downloading file to local"
            ) as progress:
                while True:
                    data = data_socket.recv(4096)
                    if not data:
                        break
                    file.write(data)
                    progress.update(len(data))
            data_socket.close()
            if listen_socket:
                listen_socket.close()
            response = self.recv_response()
            print(response)
        except Exception as e:
            print(f"Error when download file: {e}")
            if listen_socket:
                listen_socket.close()

    def set_transfer_mode(self, mode_sign):
        mode_sign = mode_sign.upper()
        if mode_sign not in ['A', 'I']:
            print("Invalid mode. Please choose A(ASCII) or I(Binary)")
            return
        mode_name = str()
        if mode_sign == 'A':
            mode_name = "ASCII"
        else:
            mode_name = "Binary"
        print(f"Set transfer mode to {mode_name}")
        self.send_command(f"TYPE {mode_sign}")
        response = self.recv_response()
        print(response)
        if response.startswith("200"):
            self.transfer_mode = mode_sign

    def show_status(self):
        print("\n--- Current Status ---")
        self.send_command("STAT")
        response = self.recv_response()
        print(response)

    def close(self):
        if self.control_socket:
            self.send_command("QUIT")
            response = self.recv_response()
            print(response)
            self.control_socket.close()
            print("Connection has been closed")

if __name__ == "__main__":
    client = ClientSocket("127.0.0.1", 21)
    if client.connect():
        if client.login("YuukiT", "151106"):
            client.list_files()
            client.put_file("README.md")
            client.list_files()
        client.close()