import socket
import ssl
import os
import shutil
import subprocess as sp
import sys
import time
from tqdm import tqdm
import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
import threading
import queue

class ProgressCallback:
    """
        Progress tracking callback for file transfer operations.

        Provides a unified interface for updating progress bars
        in both GUI and command-line environments.

        Attributes:
            gui: GUI reference for progress updates
            total (int): Total bytes to transfer
            desc (str): Description of current operation
            current (int): Current bytes transferred
    """
    def __init__(self, gui, total, desc):
        self.gui = gui
        self.total = total
        self.desc = desc
        self.current = 0
        self.gui.show_progress(f"{desc}: 0%", 0)
    
    def update(self, n):
        """
            Update progress with n bytes transferred.

            Increments current transfer count and calculates percentage
            completion. Updates GUI progress bar with new percentage.

            Args:
                n (int): Number of bytes transferred in this update
        """
        self.current += n
        if self.total > 0:
            progress = self.current / self.total
            percentage = int(progress * 100)
            self.gui.show_progress(f"{self.desc}: {percentage}%", progress)
    
    def close(self):
        """
            Hide progress bar when operation completes.

            Cleans up progress display by hiding the progress bar
            and clearing progress text.
        """
        self.gui.hide_progress()

class ClientSocket:
    """
        Sercue FTP Client Socket

         Handles all network communication with FTP servers including:
        - Connection establishment and authentication
        - File transfer operations (upload/download)
        - Directory navigation and management
        - Security scanning integration

         Attributes:
            host (str): FTP server hostname/IP
            port (int): FTP server port (default: 21)
            control_socket: Main control connection socket
            context: SSL context for secure connections
            transfer_mode (str): Current transfer mode ('A' for ASCII, 'I' for Binary)
            is_passive (bool): Connection mode flag
            logger: Callback function for logging
            gui: GUI reference for progress updates
    """
    # Class variable to track ClamAV agent process
    _clamav_agent_process = None
    
    def __init__(self, host, port=21, logger_callback=None, gui=None):
        self.control_socket = None
        self.is_passive = True # Set default connection mode to passive
        self.host = host
        self.port = port
        self.context = None
        self.transfer_mode = 'I'  # Set default transfer mode to Binary
        self.logger = logger_callback
        self.gui = gui

    def recv_response(self):
        """
            Receive and decode response from FTP server.

            Reads data from the control socket and decodes it as UTF-8 string.
            Used for all FTP command responses.

            Returns:
                str: Server response as decoded string
        """
        return self.control_socket.recv(4096).decode()

    def send_command(self, cmd):
        """
            Send command to FTP server with proper line ending.

            Ensures all commands end with CRLF (\r\n) as required by FTP protocol.
            Encodes command as UTF-8 bytes before sending.

            Args:
                cmd (str): FTP command to send (e.g., "USER", "PASS", "LIST")
        """
        if not cmd.endswith("\r\n"):
            cmd += "\r\n"
        self.control_socket.send(cmd.encode())

    def connect(self):
        """
            Establish control connection to FTP server.

            Return:
                bool: True if connection successful, False otherwise
        """
        try:
            self.control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.control_socket.settimeout(10) # set 10 seconds to wait for the connection
            self.control_socket.connect((self.host, self.port))
            response = self.recv_response()
            self.logger(response)
            return True

        except Exception as e:
            self.logger(f"Error connection: {e}")
            return False

    def login(self, username, password):
        """
            Authenticate with FTP server using TLS encryption

            Security considerations:
            - Disables hostname verification, certificate verification because the main purpose of this project is
            just Socket so we only make this for someone who hasn't turned off TLS verify on FileZilla can run

            Authentication flow:
            1. Send AUTH TLS command
            2. Wrap socket with SSL context
            3. Send USER and PASS commands
            4. Set protection level to Private (PROT P)

            Args:
                username (str): FTP username
                password (str): FTP password

            Returns:
                bool: True if authentication successful, False otherwise
        """
        try:
            # Request TLS encryption
            self.send_command("AUTH TLS")
            response = self.recv_response()
            self.logger(response)

            if response.startswith("234"):
                # Create SSL context for secure connection
                self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                self.context.check_hostname = False
                self.context.verify_mode = ssl.CERT_NONE
                self.control_socket = self.context.wrap_socket(self.control_socket, server_hostname=self.host)

            # Send authentication credentials
            self.send_command(f"USER {username}")
            response = self.recv_response()
            self.logger(response)

            self.send_command(f"PASS {password}")
            response = self.recv_response()
            self.logger(response)

            if response.startswith("230"):
                # Set protection level to Private for secure data transfer
                self.send_command("PROT P")
                response = self.recv_response()
                self.logger(response)
                self.set_transfer_mode('I')
                return True
            return False

        except Exception as e:
            self.logger(f"Error login: {e}")
            return False

    def passive_mode(self):
        """
            Establish passive mode data connection.

            Passive mode allows the client to connect to the server's
            data port, which is useful when client is behind firewall.

            Returns:
                socket.socket: Connected data socket

            Raises:
                Exception: If PASV response cannot be parsed
        """
        self.logger("Setting Passive mode")
        self.send_command("PASV")
        response = self.recv_response()
        self.logger(response)

        # Parse PASV response format: (h1,h2,h3,h4,p1,p2)
        res = response.split(' ')
        if not res:
            raise Exception("Unable to analyze PASV response")

        # Extract host and port from PASV response
        res[-1] = res[-1][:-3] # Remove trailing characters
        data_channel = str(res[-1]).split(',')
        data_channel[0] = data_channel[0][1:] # Remove opening parenthesis

        # Construct host IP from individual octets
        data_host = f"{data_channel[0]}.{data_channel[1]}.{data_channel[2]}.{data_channel[3]}"

        # Calculate port number: p1*256 + p2
        data_port = int(data_channel[-2]) * 256 + int(data_channel[-1])


        self.logger(f"Connecting to Data Channel at {data_host}:{data_port}")
        data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data_socket.connect((data_host, data_port))
        return data_socket

    def active_mode(self):
        """
            Establish active mode data connection.

            Active mode requires the server to connect to the client's
            data port. This mode may not work if client is behind firewall.

            Returns:
                socket.socket: Listening socket for data connection
        """
        self.logger("Setting Active mode")
        listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_socket.bind(("", 10806))
        listen_socket.listen(1)

        # Get client IP and construct PORT command
        ip, port = self.control_socket.getsockname()
        h1, h2, h3, h4 = map(int, ip.split('.'))
        p1 = 10806 // 256
        p2 = 10806 % 256
        command = f"PORT {h1},{h2},{h3},{h4},{p1},{p2}"

        self.send_command(command)
        response = self.recv_response()
        self.logger(response)
        if not response.startswith("200"):
            raise Exception("Server refused PORT command")
        self.logger(f"Client is listening for data connection at {ip}:10806")
        return listen_socket

    def get_data_socket(self, cmd):
        """
            Get data socket for file transfer operations.

            Establishes data connection based on current mode (passive/active)
            and sends the specified command to prepare for data transfer.

            Args:
                cmd (str): FTP command to send ("STOR", "RETR", "LIST",...)

            Returns:
                tuple: (data_socket, listen_socket) where listen_socket may be None if connection mode is passive
        """
        listen_socket = None
        data_socket = None

        if self.is_passive:
            data_socket = self.passive_mode()

        else:
            listen_socket = self.active_mode()

        self.send_command(cmd)

        if not self.is_passive:
            self.logger("Waiting for server to connect")
            data_socket, adr = listen_socket.accept()
            self.logger("Connection completed")

        return data_socket, listen_socket

    def list_files(self):
        """
            List files and directories on FTP server.

            Returns:
                str: Directory listing as string, or None if failed
        """
        listen_socket = None
        data_socket, listen_socket = self.get_data_socket("LIST")
        data_socket = self.context.wrap_socket(data_socket, session=self.control_socket.session)

        response = self.recv_response()
        self.logger(response)

        if not response.startswith("150"):
            data_socket.close()
            return

        # Read directory listing
        folder_list = ""
        while True:
            data = data_socket.recv(4096).decode()
            if not data:
                break
            folder_list += data

        data_socket.close()
        if listen_socket:
            listen_socket.close()

        response = self.recv_response()
        self.logger(response)
        return folder_list

    def change_directory_server(self, directory):
        """
            Change the current working directory on the FTP server.

            Args:
                directory (str): Path to the directory to change to on server
        """
        self.logger(f"Change directory on server '{directory}'")
        self.send_command(f"CWD {directory}")
        response = self.recv_response()
        self.logger(response)

    def change_directory_local(self, directory):
        """
            Change the current working directory on local system.

            Args:
                directory (str): Path to the local directory to change to
        """
        try:
            # Check whether new directory path was existed or not
            if os.path.exists(directory) and os.path.isdir(directory):
                self.logger(f"Local directory set to: {os.path.abspath(directory)}")
            else:
                self.logger(f"Local directory '{directory}' is not available")

        except Exception as e:
            self.logger(f"Error when setting local directory: {e}")

    def print_current_server_directory(self):
        """
            Display the current working directory on the FTP server.
        """
        self.send_command("PWD")
        response = self.recv_response()
        self.logger(response)

    def make_directory(self, directory_name):
        """
            Create a new directory on the FTP server.

            Args:
                directory_name (str): Name of the directory to create on server
        """
        self.logger(f"Creating directory {directory_name}")
        self.send_command(f"MKD {directory_name}")
        response = self.recv_response()
        self.logger(response)

    def remove_server_directory(self, directory_name):
        """
            Delete a directory on the FTP server.

            Args:
                directory_name (str): Name of the directory to delete on server
        """
        self.logger(f"Removing directory {directory_name}")
        self.send_command(f"RMD {directory_name}")
        response = self.recv_response()
        self.logger(response)
        
    def remove_local_directory(self, directory_name):
        """
            Delete a directory on the local file system.

            Args:
                directory_name (str): Path to the local directory to delete
        """
        try:
            # Use shutil to delete folder that has items inside
            shutil.rmtree(directory_name)

        except FileNotFoundError:
            print("Folder not exist")

        except PermissionError:
            print("You don't have permission to delete this!")

    def delete_server_file(self, file_name):
        """
            Delete a file on the FTP server.

            Args:
                file_name (str): Name of the file to delete on server
        """
        self.logger(f"Deleting file {file_name}")
        self.send_command(f"DELE {file_name}")
        response = self.recv_response()
        self.logger(response)
        
    def delete_local_file(self, file_name):
        """
            Delete a file on the local file system.
            Args:
                file_name (str): Path to the local file to delete
        """
        try:
            os.remove(file_name)

        except FileNotFoundError:
            self.logger("File not exist")

        except PermissionError:
            self.logger("You don't have permission to delete this!")

    def rename_server_file(self, original_name, new_name):
        """
            Rename a file on the FTP server.

            Args:
                original_name (str): Current name of the file on server
                new_name (str): New name for the file on server
        """
        self.logger(f"Change file name from {original_name} to {new_name}")
        self.send_command(f"RNFR {original_name}")

        response = self.recv_response()
        if response.startswith("350"):
            self.send_command(f"RNTO {new_name}")
            response = self.recv_response()
            self.logger(response)

        else:
            self.logger("Error: Server is nor ready for changing name")
        
    def rename_local_file(self, original_name, new_name):
        """
            Rename a file on the local file system.

            Args:
                original_name (str): Current path and name of the local file
                new_name (str): New path and name for the local file
        """
        self.logger(f"Change file name from {original_name} to {new_name}")

        try:
            os.rename(original_name, new_name)

        except FileNotFoundError:
            self.logger("File/folder not exist")

        except FileExistsError:
            self.logger("New name already exist")

        except PermissionError:
            self.logger("You don't have permission to change this!")

    def get_file_size(self, filename):
        """
            Get the size in bytes of a file on the FTP server.

            Args:
                filename (str): Name of the file on server to get size for

            Returns:
                int: File size in bytes, or -1 if error occurs
        """
        try:
            self.send_command(f"SIZE {filename}")
            response = self.recv_response()
            if response.startswith("213"):
                return int(response.split(" ")[1])
            return -1

        except Exception:
            return -1

    def scan_file_with_ClamAVAgent(self, filename):
        """
            Scan file for malware using ClamAV agent.

            Process:
            1. Start ClamAV agent process (if not already running)
            2. Connect to agent socket (127.0.0.1:15116)
            3. Send file metadata (filename + size)
            4. Stream file content to agent
            5. Receive scan result (CLEAN/INFECTED)

            Timeout calculation:
            - Base timeout: 45 seconds
            - Additional time: 4 seconds per MB of file size

            Args:
                filename (str): Path to file to scan

            Returns:
                bool: True if file is clean, False if infected or error
        """
        self.logger(f"Scanning {filename} with ClamAVAgent")
        clamav_host = "127.0.0.1"
        clamav_port = 15116

        # Start ClamAV agent if not running
        if not self._clamav_agent_process or self._clamav_agent_process.poll() is not None:
            self.logger("Starting ClamAV agent...")
            script_dir = os.path.dirname(os.path.abspath(__file__))
            clamav_agent_path = os.path.join(script_dir, "clamav_agent.py")
            cmd = [sys.executable, clamav_agent_path]
            self._clamav_agent_process = sp.Popen(cmd, text=True)
            time.sleep(3)  # Wait for agent to initialize

        max_retries = 3
        for attempt in range(max_retries):
            try:
                agent_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                # Calculate timeout based on file size(MB)
                filesize = os.path.getsize(filename)
                filesize_mb = os.path.getsize(filename) / (1024 * 1024)
                agent_socket.settimeout(45 + filesize_mb * 4)

                agent_socket.connect((clamav_host, clamav_port))
                
                # <SEPERATOR> is the signal for the agent to split file and filesize when receive
                agent_socket.send(f"{filename}<SEPARATOR>{filesize}".encode())

                # Stream file content with progress tracking
                if self.gui:
                    progress = ProgressCallback(self.gui, filesize, "Uploading file to ClamAV Agent")
                else:
                    progress = tqdm(total=filesize, unit='B', unit_scale=1024, desc="Uploading file to ClamAV Agent")

                # Send file agent socket
                with open(filename, "rb") as file:
                    while True:
                        data = file.read(4096)
                        if not data:
                            break
                        agent_socket.sendall(data)
                        progress.update(len(data))
                
                progress.close()

                # Receive scan result
                result = agent_socket.recv(4096).decode()
                agent_socket.close()
                if result == "CLEAN":
                    return True
                else:
                    return False

            except socket.error as e:
                self.logger(f"Unexpected error with agent (attempt {attempt + 1}): {e}")
                if attempt < max_retries - 1:
                    self.logger("Restarting ClamAV agent due to error...")
                    self.__class__.restart_clamav_agent()
                    time.sleep(2)  # Wait before retry
                else:
                    self.logger("All retry attempts failed")
                    return False
            except socket.timeout as e:
                self.logger(f"Timeout error with agent (attempt {attempt + 1}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(2)  # Wait before retry
                else:
                    self.logger("All retry attempts failed")
                    return False
            except Exception as e:
                self.logger(f"Unexpected error with agent (attempt {attempt + 1}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(2)  # Wait before retry
                else:
                    self.logger("All retry attempts failed")
                    return False
            finally:
                try:
                    agent_socket.close()
                except:
                    pass

        return False

    def put_file(self, local_filename, server_filename = None):
        """
            Upload a file to the FTP server with security scanning.

            This method performs the following steps:
            1. Validates file existence
            2. Scans file with ClamAV for malware detection
            3. Establishes data connection in current mode (passive/active)
            4. Transfers file with progress tracking

            Args:
                local_filename (str): Path of local file to upload
                server_filename (str, optional): Target filename on server.
                                               If None, use local filename

            Raises:
                FileNotFoundError: If local file doesn't exist
                ConnectionError: If network connection fails
                SecurityError: If file fails antivirus scan
        """

        # Validate file existence
        if not os.path.exists(local_filename):
            self.logger(f"File {local_filename} does not exist")
            return

        # Security scan before upload
        if not self.scan_file_with_ClamAVAgent(local_filename):
            self.logger("This file is not safe")
            return

        # Use local filename if server filename not given
        if not server_filename:
            server_filename = os.path.basename(local_filename)

        listen_socket = None
        try:
            # Establish data connection for file upload
            data_socket, listen_socket = self.get_data_socket(f"STOR {server_filename}")
            data_socket = self.context.wrap_socket(data_socket, session=self.control_socket.session)

            response = self.recv_response()
            self.logger(response)
            if not response.startswith("150"):
                data_socket.close()
                if listen_socket:
                    listen_socket.close()
                return
            filesize = os.path.getsize(local_filename)

            # Transfer file with progress tracking
            if self.gui:
                progress = ProgressCallback(self.gui, filesize, "Uploading to server")
            else:
                progress = tqdm(total=filesize, unit='B', unit_scale=1024, desc="Uploading to server")

            # Send file to server socket
            with open(local_filename, 'rb') as file:
                while True:
                    data = file.read(4096)
                    if not data:
                        break
                    data_socket.sendall(data)
                    progress.update(len(data))
            

            progress.close()
            data_socket.close()

            if listen_socket:
                listen_socket.close()

            response = self.recv_response()
            self.logger(response)

        except Exception as e:
            self.logger(f"Error when putting file: {e}")
            if listen_socket:
                listen_socket.close()

    def put_folder(self, local_folder, server_folder = None):
        """
            Upload an entire folder to the FTP server recursively.

            Creates folder structure on server and uploads all files and subfolders.
            Uses recursive approach to handle nested directory structures.

            Args:
                local_folder (str): Path to the local folder to upload
                server_folder (str, optional): Name for the folder on server.
                                             If None, uses local folder name
        """

        # Validate folder existence
        if not os.path.exists(local_folder):
            self.logger(f"Folder {local_folder} does not exist")
            return

        # Use local folder if server folder not given
        if not server_folder:
            server_folder = os.path.basename(local_folder)

        try:
            self.make_directory(server_folder)
            self.change_directory_server(server_folder)

            # Recursive upload
            for item in os.listdir(local_folder):
                item_path = os.path.join(local_folder, item)
                if os.path.isfile(item_path):
                    self.logger(f"Uploading file: {item}")
                    self.put_file(item_path)
                else:
                    self.logger(f"Uploading folder: {item}")
                    self.put_folder(item_path)
            self.change_directory_server("..")

        except Exception as e:
            self.logger(f"Error when putting folder: {e}")

    def down_file(self, server_filename, local_filename = None):
        """
            Download a file from the FTP server to local system.

            Establishes data connection and downloads file with progress tracking.
            Uses current transfer mode (binary/ASCII) for download.

            Args:
                server_filename (str): Name of the file on server to download
                local_filename (str, optional): Local filename for downloaded file.
                                              If None, uses server filename
        """

        # Use server filename if local filename not given
        if not local_filename:
            local_filename = server_filename

        # Resolve destination path into GUI's local directory (if available)
        base_dir = self.gui.local_path if (self.gui and getattr(self.gui, "local_path", None)) else "."
        target_path = local_filename if os.path.isabs(local_filename) else os.path.join(base_dir, local_filename)
        target_dir = os.path.dirname(target_path)
        if target_dir:
            os.makedirs(target_dir, exist_ok=True)

        listen_socket = None

        try:
            filesize = self.get_file_size(server_filename)
            data_socket, listen_socket = self.get_data_socket(f"RETR {server_filename}")
            data_socket = self.context.wrap_socket(data_socket, session=self.control_socket.session)

            response = self.recv_response()
            self.logger(response)
            if not response.startswith("150"):
                data_socket.close()
                if listen_socket:
                    listen_socket.close()
                return

            # Transfer file with progress tracking
            if self.gui and filesize != -1:
                progress = ProgressCallback(self.gui, filesize, "Downloading file to local")
            else:
                progress = tqdm(total=filesize if filesize != -1 else None, unit='B', unit_scale=1024, desc="Downloading file to local")

            # Get file from server socket
            with open(target_path, 'wb') as file:
                while True:
                    data = data_socket.recv(4096)
                    if not data:
                        break
                    file.write(data)
                    progress.update(len(data))
            
            progress.close()
            data_socket.close()
            if listen_socket:
                listen_socket.close()

            response = self.recv_response()
            self.logger(response)

        except Exception as e:
            self.logger(f"Error when download file: {e}")
            if listen_socket:
                listen_socket.close()

    def down_folder(self, server_folder, local_folder = None):
        """
            Download an entire folder from the FTP server recursively.

            Creates local folder structure and downloads all files and subfolders.
            Uses recursive approach to handle nested directory structures.

            Args:
                server_folder (str): Name of the folder on server to download
                local_folder (str, optional): Local folder name for downloaded folder.
                                            If None, uses server folder name
        """

        # Determine base local directory from GUI
        base_dir = self.gui.local_path if (self.gui and getattr(self.gui, "local_path", None)) else "."

        # Use server folder if local folder not given
        if not local_folder:
            local_folder = server_folder

        # Resolve absolute target root for this folder
        target_root = local_folder if os.path.isabs(local_folder) else os.path.join(base_dir, local_folder)

        try:
            os.makedirs(target_root, exist_ok=True)
        except Exception as e:
            self.logger(f"Error creating directory {target_root}: {e}")
            return

        try:
            # Move to the directory that need to download (server-side)
            self.change_directory_server(server_folder)

            list_file = self.list_files()
            if list_file:
                # Recursive download items
                for line in list_file.splitlines():
                    if line.strip() and len(line.split()) >= 9:
                        parts = line.split()
                        name = " ".join(parts[8:])
                        item_type = "Folder" if parts[0].startswith('d') else "File"
                        if name in [".", ".."]:
                            continue
                        if item_type == "File":
                            self.down_file(name, os.path.join(target_root, name))
                        else:
                            self.down_folder(name, os.path.join(target_root, name))

            # Move back to the original server directory
            self.change_directory_server("..")

        except Exception as e:
            self.logger(f"Error downloading folder {server_folder}: {e}")

    def set_transfer_mode(self, mode_sign):
        """
            Set the file transfer mode (ASCII or Binary).

            Args:
                mode_sign (str): Transfer mode - 'A' for ASCII, 'I' for Binary
        """

        mode_sign = mode_sign.upper()

        # Check valid mode sign
        if mode_sign not in ['A', 'I']:
            self.logger("Invalid mode. Please choose A(ASCII) or I(Binary)")
            return

        mode_name = str()
        if mode_sign == 'A':
            mode_name = "ASCII"
        else:
            mode_name = "Binary"

        self.logger(f"Set transfer mode to {mode_name}")
        self.send_command(f"TYPE {mode_sign}")

        response = self.recv_response()
        self.logger(response)
        if response.startswith("200"):
            self.transfer_mode = mode_sign

    def show_status(self):
        """
            Display current FTP connection status and server information.
        """
        self.logger("\n--- Current Status ---")
        self.send_command("STAT")
        response = self.recv_response()
        self.logger(response)

    def close(self):
        """
            Close the FTP connection gracefully.
        """
        if self.control_socket:
            self.send_command("QUIT")
            response = self.recv_response()
            self.logger(response)
            self.control_socket.close()
            self.logger("Connection has been closed")
    
    @classmethod
    def cleanup_clamav_agent(cls):
        """
            Clean up the ClamAV agent process.
        """
        if cls._clamav_agent_process and cls._clamav_agent_process.poll() is None:
            cls._clamav_agent_process.terminate()
            cls._clamav_agent_process = None

    @classmethod
    def restart_clamav_agent(cls):
        """
            Restart the ClamAV agent process.
        """
        cls.cleanup_clamav_agent()
        time.sleep(1)  # Wait for process to terminate
        script_dir = os.path.dirname(os.path.abspath(__file__))
        clamav_agent_path = os.path.join(script_dir, "clamav_agent.py")
        cmd = [sys.executable, clamav_agent_path]
        cls._clamav_agent_process = sp.Popen(cmd, text=True)
        time.sleep(3)  # Wait for agent to initialize

class GUI(ctk.CTk):
    """
        Secure FTP Client Graphical User Interface

        Provides a modern GUI for FTP operations with features including:
        - Connection management with TLS support
        - File/folder upload/download with progress tracking
        - Directory navigation and file management
        - Security scanning integration
        - Dual-panel file browser (local and server)

        Attributes:
            client: FTP client socket instance
            log_queue: Queue for thread-safe logging
            local_path: Current local directory path
    """
    def __init__(self):
        super().__init__()

        #Set up the GUI layout
        self.title("Secure FTP Client")
        self.geometry("1400x900")
        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=0)
        self.grid_rowconfigure(2, weight=1)
        self.grid_rowconfigure(3, weight=0)
        self.grid_columnconfigure(0, weight=1)


        self.client = None
        self.log_queue = queue.Queue()
        self.local_path = "."
        self.create() # Start create the interface
        self.after(100, self.process_log_queue) # Start the log queue to update every 100ms
        # --- Transfer pipeline (non-blocking GUI)
        # A single background worker consumes jobs from a thread-safe Queue.
        # GUI actions enqueue logical transfer jobs; the worker performs all
        # network I/O sequentially to avoid concurrent access to the control/data
        # sockets and to keep the UI responsive.
        self.transfer_queue = queue.Queue()
        self.transfer_cancel = threading.Event()

        # Single worker sequentially processes all transfer tasks
        self.transfer_worker = threading.Thread(target=self._transfer_worker, daemon=True)
        self.transfer_worker.start()

        # Suppress transient FTP data errors in logs (425/ECONNABORTED)
        self.suppress_transient_errors = True

    def create(self):
        """
            Create and configure all GUI components.
            Sets up connection frame, file browsers, progress bars,
            and context menus for file operations.
        """

        # Connection frame
        self.connect_frame = ctk.CTkFrame(self)
        self.connect_frame.grid(row=0, column=0, padx=10, pady=10, sticky='ew')
        self.connect_frame.grid_columnconfigure((1, 3, 5, 7), weight=1)

        self.host_label = ctk.CTkLabel(self.connect_frame, text="Server IP:")
        self.host_label.grid(row=0, column=0, padx=(10, 5), pady=10)
        self.host_entry = ctk.CTkEntry(self.connect_frame, placeholder_text="Enter Server IP")
        self.host_entry.grid(row=0, column=1, padx=(5, 10), pady=10, sticky="ew")

        self.port_label = ctk.CTkLabel(self.connect_frame, text="Port:")
        self.port_label.grid(row=0, column=2, padx=(10, 5), pady=10)
        self.port_entry = ctk.CTkEntry(self.connect_frame, placeholder_text="Enter port")
        self.port_entry.grid(row=0, column=3, padx=(5, 10), pady=10, sticky="ew")

        self.username_label = ctk.CTkLabel(self.connect_frame, text="Username:")
        self.username_label.grid(row=0, column=4, padx=(10, 5), pady=10)
        self.username_entry = ctk.CTkEntry(self.connect_frame, placeholder_text="Enter username")
        self.username_entry.grid(row=0, column=5, padx=(5, 10), pady=10, sticky="ew")

        self.pass_label = ctk.CTkLabel(self.connect_frame, text="Password:")
        self.pass_label.grid(row=0, column=6, padx=(10, 5), pady=10)
        self.pass_entry = ctk.CTkEntry(self.connect_frame, placeholder_text="Enter password", show="*")
        self.pass_entry.grid(row=0, column=7, padx=(5, 10), pady=10, sticky="ew")

        self.connect_button = ctk.CTkButton(self.connect_frame, text="Connect", command=self.toggle_connection, fg_color= "#7FDE7C", text_color="#753096", hover_color="#3B9C3A")
        self.connect_button.grid(row=0, column=8, padx=10, pady=10)

        self.switch_var = ctk.StringVar(value="off")
        self.mode_switch = ctk.CTkSwitch(self.connect_frame, text="Mode:", variable=self.switch_var, onvalue="on", offvalue="off", command=self.switch_mode)
        self.mode_switch.grid(row=0, column=9, padx=(10, 5), pady=10)
        self.mode_text = ctk.CTkLabel(self.connect_frame, text="Passive", text_color="cyan")
        self.mode_text.grid(row=0, column=10, padx=(5, 10), pady=10)


        # General function frame
        self.option_frame = ctk.CTkFrame(self, height=40)
        self.option_frame.grid(row=1, column=0, padx=10, pady=0, sticky="ew")
        self.refresh_button = ctk.CTkButton(self.option_frame, text="Refresh", width=100, fg_color="green", hover_color="#3B6637", corner_radius=40, command=self.refresh)
        self.refresh_button.pack(side="left", padx=5, pady=5)
        self.show_status_button = ctk.CTkButton(self.option_frame, text="Show status", width=100, corner_radius=40, command=self.show_status)
        self.show_status_button.pack(side="left", padx=5, pady=5)
        self.change_ldir_button = ctk.CTkButton(self.option_frame, text="Change local directory", width=100, corner_radius=40, command=self.change_local_dir)
        self.change_ldir_button.pack(side="left", padx=5, pady=5)
        self.change_sdir_button = ctk.CTkButton(self.option_frame, text="Change server directory", width=100, corner_radius=40, command=self.change_server_dir)
        self.change_sdir_button.pack(side="left", padx=5, pady=5)
        self.show_dir_button = ctk.CTkButton(self.option_frame, text="Show server directory", width=100, corner_radius=40, command=self.show_server_dir)
        self.show_dir_button.pack(side="left", padx=5, pady=5)
        self.add_dir_button = ctk.CTkButton(self.option_frame, text="Make server directory", width=100, corner_radius=40, command=self.add_server_dir)
        self.add_dir_button.pack(side ="left", padx=5, pady=5)
        self.help_button = ctk.CTkButton(self.option_frame, text="Help", fg_color="pink", text_color="#969289", hover_color="#824569", width=100, corner_radius=40, command=self.show_help)
        self.help_button.pack(side="right", padx=5, pady=5)
        self.transferMode_button = ctk.CTkButton(self.option_frame, text = "Transfer mode: Binary", width=100, corner_radius=40, command=self.change_transferMode)
        self.transferMode_button.pack(side = "left", padx=5, pady =5)


        # Dual panel file browser
        paned_window = tk.PanedWindow(self, orient=tk.HORIZONTAL, sashrelief=tk.RAISED, bg="#2b2b2b")
        paned_window.grid(row=2, column=0, padx=10, pady=5, sticky="nsew")

        local_frame = ctk.CTkFrame(paned_window)
        local_frame.grid_rowconfigure(1, weight=1)
        local_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(local_frame, text="Local Directory", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, pady=5)

        style = self.create_treeview_style()
        self.local_tree = ttk.Treeview(local_frame, columns=("size", "type"), show="tree headings",style="Custom.Treeview", selectmode="extended")
        self.local_tree.heading("#0", text="Name")
        self.local_tree.heading("size", text="Size")
        self.local_tree.heading("type", text="Type")
        self.local_tree.grid(row=1, column=0, sticky="nsew")
        paned_window.add(local_frame, width=700)

        remote_frame = ctk.CTkFrame(paned_window)
        remote_frame.grid_rowconfigure(1, weight=1)
        remote_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(remote_frame, text="Server Directory", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0,pady=5)

        self.remote_tree = ttk.Treeview(remote_frame, columns=("size", "type"), show="tree headings", style="Custom.Treeview", selectmode="extended")
        self.remote_tree.heading("#0", text="Name")
        self.remote_tree.heading("size", text="Size")
        self.remote_tree.heading("type", text="Type")
        self.remote_tree.grid(row=1, column=0, sticky="nsew")
        paned_window.add(remote_frame, width=700)


        # File function menu
        self.option_menu()
        self.local_tree.bind("<Button-3>", self.show_local_menu)
        self.remote_tree.bind("<Button-3>", self.show_remote_menu)

        self.log_frame = ctk.CTkFrame(self)
        self.log_frame.grid(row=3, column=0, padx=10, pady=10, sticky="ew")
        self.log_frame.grid_rowconfigure(0, weight=1)
        self.log_frame.grid_columnconfigure(0, weight=1)

        self.log_box = ctk.CTkTextbox(self.log_frame, height=120)
        self.log_box.grid(row=0, column=0, sticky="nsew")
        self.log_box.configure(state="disabled")
        
        self.progress_frame = ctk.CTkFrame(self.log_frame)
        self.progress_frame.grid(row=1, column=0, sticky="ew", pady=(5,0))
        
        self.progress_label = ctk.CTkLabel(self.progress_frame, text="", font=ctk.CTkFont(size=12))
        self.progress_label.pack(side="left", padx=(10,5))
        
        self.progress_bar = ctk.CTkProgressBar(self.progress_frame)
        self.progress_bar.pack(side="left", fill="x", expand=True, padx=(5,10))
        self.progress_bar.set(0)
        self.progress_frame.grid_remove()

    def create_treeview_style(self):
        """
            Create custom styling for file browser treeviews.

            Returns:
                ttk.Style: Configured style object for treeviews
        """
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Custom.Treeview", background="#2b2b2b", foreground="white", rowheight=25, fieldbackground="#2b2b2b")
        style.map('Custom.Treeview', background=[('selected', '#1f6aa5')])
        style.configure("Custom.Treeview.Heading", background="#565b5e", foreground="white", relief="flat")
        style.map("Custom.Treeview.Heading", background=[('active', '#343638')])
        return style

    def option_menu(self):
        """
            Create context menus for file operations.

            Sets up right-click menus for both local and remote
            file browsers with upload, download, delete, and rename options.
        """
        self.local_menu = tk.Menu(self, tearoff=0, bg="#2b2b2b", fg="white")
        self.local_menu.add_command(label="Upload", command=self.upload_selected)
        self.local_menu.add_command(label="Delete", command=self.delete_selected_local)
        self.local_menu.add_command(label="Rename", command=self.rename_selected_local)
        self.remote_menu = tk.Menu(self, tearoff=0, bg="#2b2b2b", fg="white")
        self.remote_menu.add_command(label="Download", command=self.download_selected)
        self.remote_menu.add_command(label="Delete", command=self.delete_selected_remote)
        self.remote_menu.add_command(label="Rename", command=self.rename_selected_remote)

    def show_local_menu(self, event):
        """
            Display context menu for local file browser.

            Shows menu only if files/folders are selected.

            Args:
                event: Right-click event object
        """
        self.local_tree.identify_row(event.y)
        if self.local_tree.selection():
            self.local_menu.post(event.x_root, event.y_root)

    def show_remote_menu(self, event):
        """
            Display context menu for remote file browser.

            Shows menu only if files/folders are selected.

            Args:
                event: Right-click event object
        """
        self.remote_tree.identify_row(event.y)
        if self.remote_tree.selection():
            self.remote_menu.post(event.x_root, event.y_root)

    def switch_mode(self):
        """
            Toggle between passive and active connection modes.

            Updates mode display text and client connection mode
            based on switch state.
        """
        mode = self.switch_var.get()
        if mode == "on":
            self.mode_text.configure(text="Active")
            if self.client and self.client.control_socket:
                self.client.is_passive = False

        else:
            self.mode_text.configure(text="Passive")
            if self.client and self.client.control_socket:
                self.client.is_passive = True

    def log(self, message):
        """
            Add message to log queue for thread-safe logging.

            Args:
                message (str): Message to be logged
        """
        self.log_queue.put(message)

    def process_log_queue(self):
        """
            Process queued log messages and display in log box.

            Runs periodically to handle thread-safe logging
            from background operations.
        """
        try:
            while True:
                message = self.log_queue.get_nowait()

                # Skip transient data-channel errors if enabled
                if getattr(self, "suppress_transient_errors", False):
                    msg_upper = str(message).upper()
                    if msg_upper.startswith("425") or "ECONNABORTED" in msg_upper or "CONNECTION ABORTED" in msg_upper:
                        continue

                self.log_box.configure(state="normal")
                self.log_box.insert("end", message + "\n")
                self.log_box.see("end")
                self.log_box.configure(state="disabled")

        except queue.Empty:
            pass

        # Auto update the log after 100ms
        self.after(100, self.process_log_queue)
    
    def show_progress(self, text, value=0):
        """
            Display or update the progress UI in a thread-safe way.

            This method can be called from any thread. When invoked from a
            non-UI thread, it schedules the update on the Tk main loop via
            `after(0, ...)`, ensuring no direct cross-thread widget access.

            Args:
                text (str): Label displayed to the left of the progress bar.
                value (float): Progress in the range [0.0, 1.0]. Values outside
                    this range are forwarded to the widget unchanged.

            Behavior:
            - Reveals the hidden `progress_frame` if necessary.
            - Updates both the text label and the bar value atomically on the
              UI thread.
            - Does not force a synchronous redraw; rendering occurs naturally in
              the Tk event loop. Avoid calling `self.update()` repeatedly to
              prevent frame stutter and increased CPU usage.
        """
        def _update():
            self.progress_label.configure(text=text)
            self.progress_bar.set(value)
            self.progress_frame.grid(row=1, column=0, sticky="ew", pady=(5, 0))
            # Avoid calling self.update() repeatedly to prevent stutter
        if threading.current_thread() is threading.main_thread():
            _update()
        else:
            self.after(0, _update)

    def update_progress(self, value):
        """
            Update only the progress bar value — thread-safe.

            Args:
                value (float): Progress in the range [0.0, 1.0]. Not clamped.

            Notes:
            - This does not change the progress label text.
            - Safe to call from any thread; schedules the update on the UI
              thread when necessary.
            - Consider calling `show_progress()` once before subsequent calls to
              `update_progress()` so that the frame is visible.
        """
        def _update():
            self.progress_bar.set(value)
        if threading.current_thread() is threading.main_thread():
            _update()
        else:
            self.after(0, _update)

    def hide_progress(self):
        """
            Hide the progress UI — thread-safe.

            Behavior:
            - Hides `progress_frame` and clears the progress label.

            Notes:
            - Does not cancel any in-flight transfers; it only affects UI
              visibility.
            - Safe to call from any thread; uses `after(0, ...)` when needed.
        """
        def _update():
            self.progress_frame.grid_remove()
            self.progress_label.configure(text="")
        if threading.current_thread() is threading.main_thread():
            _update()
        else:
            self.after(0, _update)


    def refresh_remote_files(self):
        """
            Refresh the remote file browser display.

            Fetches current server directory listing and updates
            the remote tree view with file/folder information.
        """
        if not self.client:
            return

        self.log("Refresh file server list")
        file_list = self.client.list_files()
        self.remote_tree.delete(*self.remote_tree.get_children())
        if file_list:
            for line in file_list.splitlines():
                parts = line.split()
                if len(parts) >= 9:
                    name = " ".join(parts[8:])
                    size = parts[4]
                    item_type = "Folder" if parts[0].startswith('d') else "File"
                    self.remote_tree.insert("", "end", text=name, values=(f"{int(size) // 1024} KB", item_type))

    def refresh_local_files(self):
        """
            Refresh the local file browser display.

            Reads current local directory and updates local tree view
            with file/folder information and sizes.
        """
        self.local_tree.delete(*self.local_tree.get_children())

        try:
            if not os.path.exists(self.local_path):
                self.local_path = "."
                self.log("Local directory not found, resetting to current directory")
            
            for file in os.listdir(self.local_path):
                full_path = os.path.join(self.local_path, file)
                try:
                    size = os.path.getsize(full_path)
                    item_type = "Folder" if os.path.isdir(full_path) else "File"
                    self.local_tree.insert("", "end", text=file, values=(f"{size // 1024} KB", item_type))
                except OSError:
                    pass

        except Exception as e:
                self.log(f"Error when read file on local directory: {e}")

    def toggle_connection(self):
        """
            Toggle FTP connection state.

            Connects if disconnected, disconnects if connected.
            Uses threading to prevent GUI blocking during operations.
        """
        if self.client and self.client.control_socket:
            threading.Thread(target=self.disconnect, daemon=True).start()
        else:
            threading.Thread(target=self.connect, daemon=True).start()

    def connect(self):
        """
            Establish FTP connection with server.

            Creates client socket, connects to server, and authenticates.
            Updates GUI state on successful connection.
        """
        host = self.host_entry.get()
        port = self.port_entry.get()
        username = self.username_entry.get()
        password = self.pass_entry.get()

        if host != "" and port != "" and username != "" and password != "":
            self.client = ClientSocket(host, int(port), self.log, self)
            if self.client.connect():
                if self.client.login(username, password):
                    self.connect_button.configure(text = "Disconnect", fg_color="red")
                    if self.switch_var == "on":
                        self.client.is_passive = False
                    self.refresh_remote_files()
                    self.refresh_local_files()
                    self.host_entry.configure(state = "disabled")
                    self.pass_entry.configure(state = "disabled")
                    self.port_entry.configure(state = "disabled")
                    self.username_entry.configure(state = "disabled")
                else:
                    self.client.close()
                    self.client = None
            else:
                self.client = None

        else:
            messagebox.showinfo("Connect error", "Please enter full information")

    def disconnect(self):
        """
            Close FTP connection and reset GUI state.

            Closes client connection and resets all GUI elements
            to disconnected state.
        """
        if self.client:
            self.client.close()
            self.client = None
            self.remote_tree.delete(*self.remote_tree.get_children())
            self.local_tree.delete(*self.local_tree.get_children())
            self.connect_button.configure(text="Connect", fg_color="#7FDE7C")
            self.host_entry.configure(state="normal")
            self.pass_entry.configure(state="normal")
            self.port_entry.configure(state="normal")
            self.username_entry.configure(state="normal")
        
        # Clean up ClamAV agent when disconnecting
        ClientSocket.cleanup_clamav_agent()

    def refresh(self):
        """
            Refresh both local and remote file browsers.

            Updates file listings for both local and server directories.
        """
        if self.client and self.client.control_socket:
            self.refresh_remote_files()
            self.refresh_local_files()

    def show_status(self):
        """
            Display current FTP connection status.

            Shows detailed server status information in log.
        """
        if self.client and self.client.control_socket:
            self.client.show_status()

    def change_local_dir(self):
        """
            Change local directory via dialog.

            Opens input dialog for new local directory path.
            Validates path and updates local file browser.
        """
        if self.client and self.client.control_socket:
            dialog = ctk.CTkInputDialog(text="Enter your new directory path", title="Change local directory")
            new_path = dialog.get_input()
            if new_path:
                try:
                    if os.path.exists(new_path) and os.path.isdir(new_path):
                        self.local_path = new_path
                        self.client.change_directory_local(self.local_path)
                        self.refresh_local_files()
                        self.log(f"Successfully changed local directory to: {self.local_path}")
                    else:
                        messagebox.showerror("Error", f"Directory '{new_path}' does not exist or is not accessible")

                except Exception as e:
                    self.local_path = "."
                    messagebox.showerror("Error", f"Can't access directory: {str(e)}")
                    self.log(f"Failed to change local directory: {str(e)}")

    def change_server_dir(self):
        """
            Change server directory via dialog.

            Opens input dialog for new server directory path.
            Updates remote file browser after directory change.
        """
        if self.client and self.client.control_socket:
            dialog = ctk.CTkInputDialog(text="Enter your new directory path", title="Change server directory")
            self.client.change_directory_server(dialog.get_input())
            self.refresh_remote_files()
            
    def show_server_dir(self):
        """
            Display current server directory path.

            Shows current working directory on FTP server in log.
        """
        if self.client and self.client.control_socket:
            self.client.print_current_server_directory()

    def add_server_dir(self):
        """
            Add new server directory via dialog.

            Open input dialog for new server directory name.
            Updates remote file browser after directory change.
        """
        if self.client and self.client.control_socket:
            dialog = ctk.CTkInputDialog(text="Enter your new directory name", title="Make new server directory")
            self.client.make_directory(dialog.get_input())
            self.refresh_remote_files()

    def change_transferMode(self):
        """
            Toggle between Binary and ASCII transfer modes.

            Changes client transfer mode and updates button text
            to reflect current mode.
        """
        if self.client and self.client.control_socket:
            if self.transferMode_button._text == "Transfer mode: Binary":
                self.client.set_transfer_mode('A')
                self.transferMode_button.configure(text = "Transfer mode: ASCII")

            else:
                self.client.set_transfer_mode('I')
                self.transferMode_button.configure(text = "Transfer mode: Binary")


    def upload_selected(self):
        """
            Queue selected local items for upload.

            The selection is read from `self.local_tree`. For each selected item,
            a job is enqueued to `self.transfer_queue` and later executed by the
            background worker `_transfer_worker`:

            - Files: ("upload_file", (full_path, item_name))
            - Folders: ("upload_folder", (folder_path, item_name))

            Behavior:
            - Non-blocking; returns immediately after enqueueing.
            - Logs user-facing messages about the queued work.
            - Schedules a status refresh via `self.after(0, ...)`.

            Preconditions:
            - An active client connection is expected for successful execution
              of the enqueued jobs (validated at worker execution time).

            Side effects:
            - Server-side file list will be refreshed by the worker upon job
              completion.
        """
        selected_items = self.local_tree.selection()
        if not selected_items:
            self.log("No items selected for upload")
            return

        self.log(f"Queueing upload of {len(selected_items)} items...")

        for item in selected_items:
            iname = self.local_tree.item(item, "text")
            itype = self.local_tree.item(item, "values")[1]  # "File" / "Folder"
            full_path = os.path.join(self.local_path, iname)

            if itype == "Folder":
                self.transfer_queue.put(("upload_folder", (full_path, iname)))
            else:
                self.transfer_queue.put(("upload_file", (full_path, iname)))

        # Show status (non-blocking). The actual transfer is handled by the worker.
        self.after(0, self.show_transfer_status)
                
    def delete_selected_local(self):
        """
            Delete selected local files/folders.

            Processes all selected items in local file browser.
            Uses threading for non-blocking delete operations.
        """
        selected_items = self.local_tree.selection()
        for item in selected_items:
            iname = self.local_tree.item(item, "text")
            itype = self.local_tree.item(item, "values")[1] 
            full_path = os.path.join(self.local_path, iname)

            if itype == "Folder":
                thread = threading.Thread(target=self.client.remove_local_directory, args=(full_path,), daemon=True)
                thread.start()
                self.log("Remove complete")

            else:
                thread = threading.Thread(target=self.client.delete_local_file, args=(full_path,), daemon=True)
                thread.start()
                self.log("Remove complete")
        
    def rename_selected_local(self):
        """
            Rename selected local files/folders.

            Opens dialog for new name and processes rename operation.
            Uses threading for non-blocking rename operations.
        """
        selected_items = self.local_tree.selection()
        for item in selected_items:
            iname = self.local_tree.item(item, "text")
            itype = self.local_tree.item(item, "values")[1] 
            full_path = os.path.join(self.local_path, iname)

            if itype == "Folder":
                dialog = ctk.CTkInputDialog(text="Enter your new folder name", title="Rename local folder")
                new_name = dialog.get_input()
                new_full_path = os.path.join(self.local_path, new_name)
                thread = threading.Thread(target=self.client.rename_local_file, args=(full_path, new_full_path), daemon=True)
                thread.start()
                self.log("Rename complete")

            else:
                dialog = ctk.CTkInputDialog(text="Enter your new file name", title="Rename local file")
                new_name = dialog.get_input()
                new_full_path = os.path.join(self.local_path, new_name)
                thread = threading.Thread(target=self.client.rename_local_file, args=(full_path, new_full_path), daemon=True)
                thread.start()
                self.log("Rename complete")
    
    def download_selected(self):
        """
            Queue selected remote items for download.

            The selection is read from `self.remote_tree`. For each selected
            item, a job is enqueued to `self.transfer_queue` and later executed
            by the background worker `_transfer_worker`:

            - Files: ("download_file", (item_name,))
            - Folders: ("download_folder", (item_name,))

            Behavior:
            - Non-blocking; returns immediately after enqueueing.
            - Logs queued work and schedules a status refresh.

            Preconditions:
            - An active client connection is expected for successful execution
              of the enqueued jobs (validated at worker execution time).

            Side effects:
            - Local file list will be refreshed by the worker upon job
              completion.
        """
        selected_items = self.remote_tree.selection()
        if not selected_items:
            self.log("No items selected for download")
            return

        self.log(f"Queueing download of {len(selected_items)} items...")

        for item in selected_items:
            iname = self.remote_tree.item(item, "text")
            itype = self.remote_tree.item(item, "values")[1]  # "File" / "Folder"

            if itype == "Folder":
                self.transfer_queue.put(("download_folder", (iname,)))
            else:
                self.transfer_queue.put(("download_file", (iname,)))

        self.after(0, self.show_transfer_status)
    
    def get_active_transfers(self):
        """Get count of active uploads and downloads"""
        active_uploads = len(getattr(self, 'active_uploads', []))
        active_downloads = len(getattr(self, 'active_downloads', []))
        return active_uploads, active_downloads
    
    def show_transfer_status(self):
        """Show current transfer status"""
        uploads, downloads = self.get_active_transfers()
        if uploads > 0 or downloads > 0:
            self.log(f"Active transfers: {uploads} uploads, {downloads} downloads")
        else:
            self.log("No active transfers")
    
    def _transfer_worker(self):
        """
            Background worker that serially executes queued transfer jobs.

            Responsibilities:
            - Pull jobs from `self.transfer_queue` and process them one-by-one.
            - Perform all network I/O off the UI thread to keep the GUI
              responsive.
            - Update UI state (logs, list refreshes, status) via `after(0, ...)`.

            Expected job formats (op, args):
            - ("upload_file", (full_path, item_name))
            - ("upload_folder", (folder_path, item_name))
            - ("download_file", (item_name,))
            - ("download_folder", (item_name,))

            Termination:
            - Receiving a `None` job acts as a sentinel to break the loop after
              calling `task_done()`.

            Timeouts:
            - Sets a default socket timeout (30s) to avoid indefinite hangs on
              stalled connections.

            Error handling:
            - Catches exceptions per job, logs the error, and continues with the
              next job. Always calls `task_done()` in a finally block.
        """
        # Prevent sockets from hanging indefinitely
        socket.setdefaulttimeout(30)

        while True:
            job = self.transfer_queue.get()
            if job is None:
                self.transfer_queue.task_done()
                break

            op, args = job
            try:
                if op == "upload_file":
                    full_path, item_name = args
                    self.log(f"Uploading file: {item_name}")
                    self.client.put_file(full_path)
                    self.log(f"Upload file '{item_name}' complete")
                    # Refresh server view after completion
                    self.after(0, self.refresh_remote_files)

                elif op == "upload_folder":
                    folder_path, item_name = args
                    self.log(f"Uploading folder: {item_name}")
                    self.client.put_folder(folder_path)
                    self.log(f"Upload folder '{item_name}' complete")
                    self.after(0, self.refresh_remote_files)

                elif op == "download_file":
                    item_name, = args
                    self.log(f"Downloading file: {item_name}")
                    self.client.down_file(item_name)
                    self.log(f"Download file '{item_name}' complete")
                    # Refresh local view after completion
                    self.after(0, self.refresh_local_files)

                elif op == "download_folder":
                    item_name, = args
                    self.log(f"Downloading folder: {item_name}")
                    self.client.down_folder(item_name)
                    self.log(f"Download folder '{item_name}' complete")
                    self.after(0, self.refresh_local_files)

                else:
                    self.log(f"Unknown job op: {op}")

            except Exception as e:
                self.log(f"Transfer error ({op}): {e}")

            finally:
                self.transfer_queue.task_done()
                # Update overall status (non-blocking log/status message)
                self.after(0, self.show_transfer_status)

    
    def cancel_all_transfers(self):
        """Cancel all active uploads and downloads"""
        active_uploads = getattr(self, 'active_uploads', [])
        active_downloads = getattr(self, 'active_downloads', [])
        
        total_active = len(active_uploads) + len(active_downloads)
        if total_active > 0:
            self.log(f"Cancelling {total_active} active transfers...")
            # Note: Threads are daemon=True, so they will terminate when main thread ends
            # For proper cancellation, you would need to implement a cancellation mechanism
            # in the ClientSocket methods
            self.active_uploads = []
            self.active_downloads = []
            self.log("Transfer cancellation requested")
        else:
            self.log("No active transfers to cancel")
    
    def delete_selected_remote(self):
        """
            Delete selected server files/folders.

            Processes all selected items in remote file browser.
            Uses threading for non-blocking delete operations.
        """
        selected_items = self.remote_tree.selection()
        for item in selected_items:
            iname = self.remote_tree.item(item, "text")
            itype = self.remote_tree.item(item, "values")[1]

            if itype == "Folder":
                thread = threading.Thread(target=self.client.remove_server_directory, args=(iname,), daemon=True)
                thread.start()
                self.log("Remove complete")

            else:
                thread = threading.Thread(target=self.client.delete_server_file, args=(iname,), daemon=True)
                thread.start()
                self.log("Remove complete")

    def rename_selected_remote(self):
        """
            Rename selected server files/folders.

            Opens dialog for new name and processes rename operation.
            Uses threading for non-blocking rename operations.
        """
        selected_items = self.remote_tree.selection()
        for item in selected_items:
            iname = self.remote_tree.item(item, "text")
            itype = self.remote_tree.item(item, "values")[1]

            if itype == "Folder":
                dialog = ctk.CTkInputDialog(text="Enter your new folder name", title="Rename server folder")
                new_name = dialog.get_input()
                thread = threading.Thread(target=self.client.rename_server_file, args=(iname, new_name), daemon=True)
                thread.start()
                self.log("Rename complete")

            else:
                dialog = ctk.CTkInputDialog(text="Enter your new file name", title="Rename server file")
                new_name = dialog.get_input()
                thread = threading.Thread(target=self.client.rename_server_file, args=(iname, new_name), daemon=True)
                thread.start()
                self.log("Rename complete")
                
    def show_help(self):
        """
            Display help window with application usage information.

            Creates a new window with comprehensive help text
            covering all major features and operations.
        """
        help_window = ctk.CTkToplevel(self)
        help_window.title("Help - Secure FTP Client")
        help_window.geometry("600x500")
        help_window.resizable(False, False)

        help_text = """
Secure FTP Client - Help

CONNECTION:
• Enter server IP, port, username, and password
• Click Connect to establish connection
• Use Passive/Active mode switch

FILES/FOLDERS OPERATIONS:
• Right-click on files/folders for context menu
• Upload: Send local files to server
• Download: Get server files to local
• Delete: Remove files/folders
• Rename: Change file/folder names
• Use Ctrl+click for multiple selections

NAVIGATION:
• Refresh: Update file lists
• Change directories: Change server/local folders
• Show status: View connection info

SECURITY:
• All uploads are scanned with ClamAV
• Files are checked for malware before transfer
• Progress bars show scan and transfer status

***NOTE***
• Please refresh after you download/delete files/folders to show the correctly lists
        """
        
        text_box = ctk.CTkTextbox(help_window, width=580, height=450)
        text_box.pack(padx=10, pady=10)
        text_box.insert("1.0", help_text.strip())
        text_box.configure(state="disabled")
        
        close_button = ctk.CTkButton(help_window, text="Close", command=help_window.destroy, width=100)
        close_button.pack(pady=(0, 10))
        
        help_window.focus_force()
        help_window.grab_set()

if __name__ == "__main__":
    app = GUI()
    
    # Override destroy method to cleanup ClamAV agent
    original_destroy = app.destroy
    def destroy_with_cleanup():
        ClientSocket.cleanup_clamav_agent()
        original_destroy()
    app.destroy = destroy_with_cleanup
    
    app.mainloop()