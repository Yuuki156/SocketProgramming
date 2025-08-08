import socket
import os
import subprocess as sp
import time
from tqdm import tqdm

"""
Server configuration
- host: IP address to bind the agent on (loopback for local-only access)
- port: TCP port the agent listens on
"""
host = "127.0.0.1"
port = 15116

# Protocol separator between filename and filesize in the header sent by client
SEPARATOR = "<SEPARATOR>"


def scan_file(filepath: str) -> str:
    """Scan a single file with ClamAV (clamscan) and return CLEAN/INFECTED/ERROR.

    Args:
        filepath: Absolute path to the file that should be scanned.

    Returns:
        One of: "CLEAN", "INFECTED", or "ERROR".
    """
    try:
        filesize = os.path.getsize(filepath)
        # Estimate progress steps: minimum 10, roughly 1 step per MB
        estimated_steps = max(10, filesize // (1024 * 1024))
        
        cmd = ["clamscan", "--infected", filepath]
        process = sp.Popen(cmd, stdout=sp.PIPE, stderr=sp.PIPE, text=True)
        
        # Visual progress feedback while scanning
        progress_bar = tqdm(total=estimated_steps, desc="Scanning with ClamAV")
        current_step = 0
        
        # Update progress while the scan process is running
        while process.poll() is None:
            if current_step < estimated_steps:
                progress_bar.update(1)
                current_step += 1
            time.sleep(0.1)  # Update roughly every 100ms
        
        remaining = estimated_steps - current_step
        if remaining > 0:
            progress_bar.update(remaining)
        
        progress_bar.close()
        
        if process.returncode == 0:
            return "CLEAN"
        elif process.returncode == 1:
            return "INFECTED"
        else:
            return "ERROR"
    except FileNotFoundError:
        # clamscan binary not found in PATH
        print("Can't find ClamAV (clamscan). Please install ClamAV.")
        return "ERROR"
    except Exception as e:
        # Any other unexpected failure during scan execution
        print(f"Unexpected error during scan: {e}")
        return "ERROR"

if __name__ == "__main__":
    # Create a temporary directory to store the incoming file content
    temp_dir = "scan_temp_dir"
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
    
    # Create a TCP socket and listen for a single incoming connection
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(3)  # Allow up to 3 pending connections in backlog
    print(f"ClamAV Agent is listening at {host}:{port}")
    client_socket = None
    temp_filepath = None
    try:
        # Accept exactly one client in this simplified implementation
        client_socket, adr = server_socket.accept()
        print(f"Client connected from {adr}")

        # Receive the metadata header. NOTE: This assumes the entire header
        # arrives in the first recv call. For robustness, implement a loop
        # that reads until SEPARATOR is found.
        received = client_socket.recv(4096).decode()
        if SEPARATOR not in received:
            raise ValueError("Invalid metadata header (SEPARATOR not found)")

        # Parse "<filename><SEPARATOR><filesize>"
        filename, filesize = received.split(SEPARATOR)
        filename = os.path.basename(filename)
        filesize = int(filesize)
        temp_filepath = os.path.join(temp_dir, filename)
        temp_filepath = os.path.abspath(temp_filepath)
        
        # Receive exactly <filesize> bytes of file content in chunks and write to disk
        with open(temp_filepath, "wb") as file:
            bytes_received = 0
            while bytes_received < filesize:
                data = client_socket.recv(4096)
                if not data:
                    break
                file.write(data)
                bytes_received += len(data)
        
        # Run the antivirus scan and send the plain-text result
        scan_result = scan_file(temp_filepath)

        print(f"Scanning result: {scan_result}")
        client_socket.send(scan_result.encode())
    except Exception as e:
        # Top-level error handling to keep the agent from crashing silently
        print(f"Error while handling client: {e}")
    finally:
        # Always cleanup: remove temporary file and close sockets
        if temp_filepath and os.path.exists(temp_filepath):
            os.remove(temp_filepath)
        if client_socket:
            client_socket.close()
        if server_socket:
            server_socket.close()