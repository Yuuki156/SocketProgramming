import socket
import ssl

class ClientSocket:
    def __init__(self, host, port=21):
        self.control_socket = None
        self.is_passive = True
        self.host = host
        self.port = port
        self.context = None

    def recv_response(self):
        return self.control_socket.recv(4096).decode()

    def send_command(self, cmd):
        if not cmd.endswith("\r\n"):
            cmd += "\r\n"
        self.control_socket.send(cmd.encode())

    def connect(self):
        try:
            self.control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.control_socket.settimeout(15)
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

    def get_data_socket(self):
        temp_socket = None
        if self.is_passive:
            temp_socket = self.passive_mode()
        else:
            temp_socket = self.active_mode()
        self.send_command("LIST")
        if self.is_passive:
            return temp_socket
        else:
            print("Waiting for server to connect")
            data_socket, adr = temp_socket.accept()
            print("Connection completed")
            temp_socket.close()
            return data_socket

    def list_files(self):

        data_socket = self.get_data_socket()
        response = self.recv_response()
        print(response)
        if not response.startswith("150"):
            data_socket.close()
            return
        data_socket = self.context.wrap_socket(data_socket,session=self.control_socket.session)
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
            client.is_passive = True
            client.list_files()
        client.close()