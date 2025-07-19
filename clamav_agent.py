import socket
import os
import subprocess as sp

host = "127.0.0.1"
port = 15116


def scan_file(filepath):
    try:
        cmd = ["clamscan", "--no-summary", "--infected", filepath]
        result = sp.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            return "CLEAN"
        elif result.returncode == 1:
            return "INFECTED"
        else:
            return "ERROR"
    except FileNotFoundError:
        print("Can't find your ClamAV Agent")
        return "ERROR"
    except Exception as e:
        print(f"Unexpected error: {e}")
        return "ERROR"

if __name__ == "__main__":
    temp_dir = "scan_temp_dir"
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(3)
    print(f"ClamAV Agent is listening at {host}:{port}")
    client_socket = None
    temp_filepath = None
    try:
        client_socket, adr = server_socket.accept()
        received = client_socket.recv(4096).decode()
        filename, filesize = received.split("<SEPARATOR>")
        filename = os.path.basename(filename)
        filesize = int(filesize)
        temp_filepath = os.path.join(temp_dir, filename)
        temp_filepath = os.path.abspath(temp_filepath)
        with open(temp_filepath, "wb") as file:
            bytes_received = 0
            while bytes_received < filesize:
                data = client_socket.recv(4096)
                if not data:
                    break
                file.write(data)
                bytes_received += len(data)
        scan_result = scan_file(temp_filepath)
        print(f"Scanning result: {scan_result}")
        client_socket.send(scan_result.encode())
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if temp_filepath and os.path.exists(temp_filepath):
            os.remove(temp_filepath)
        if client_socket:
            client_socket.close()
        if server_socket:
            server_socket.close()