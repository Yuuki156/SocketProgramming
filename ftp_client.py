import socket
import ssl
import os
import shutil
import subprocess as sp
import sys
import time
from tqdm import tqdm
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import customtkinter as ctk
import threading
import queue

class ProgressCallback:
    def __init__(self, gui, total, desc):
        self.gui = gui
        self.total = total
        self.desc = desc
        self.current = 0
        self.gui.show_progress(f"{desc}: 0%", 0)
    
    def update(self, n):
        self.current += n
        if self.total > 0:
            progress = self.current / self.total
            percentage = int(progress * 100)
            self.gui.show_progress(f"{self.desc}: {percentage}%", progress)
    
    def close(self):
        self.gui.hide_progress()

class ClientSocket:
    def __init__(self, host, port=21, logger_callback=None, gui=None):
        self.control_socket = None
        self.is_passive = True
        self.host = host
        self.port = port
        self.context = None
        self.transfer_mode = 'I'
        self.logger = logger_callback
        self.gui = gui

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
            self.logger(response)
            return True
        except Exception as e:
            self.logger(f"Error connection: {e}")
            return False

    def login(self, username, password):
        try:
            self.send_command("AUTH TLS")
            response = self.recv_response()
            self.logger(response)
            if response.startswith("234"):
                self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                self.context.check_hostname = False
                self.context.verify_mode = ssl.CERT_NONE
                self.control_socket = self.context.wrap_socket(self.control_socket, server_hostname=self.host)
            self.send_command(f"USER {username}")
            response = self.recv_response()
            self.logger(response)
            self.send_command(f"PASS {password}")
            response = self.recv_response()
            self.logger(response)
            if response.startswith("230"):
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
        self.logger("Setting Passive mode")
        self.send_command("PASV")
        response = self.recv_response()
        self.logger(response)
        res = response.split(' ')
        if not res:
            raise Exception("Unable to analyze PASV response")
        res[-1] = res[-1][:-3]
        data_channel = str(res[-1]).split(',')
        data_channel[0] = data_channel[0][1:]
        data_host = f"{data_channel[0]}.{data_channel[1]}.{data_channel[2]}.{data_channel[3]}"
        data_port = int(data_channel[-2]) * 256 + int(data_channel[-1])
        self.logger(f"Connecting to Data Channel at {data_host}:{data_port}")
        data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data_socket.connect((data_host, data_port))
        return data_socket

    def active_mode(self):
        self.logger("Setting Active mode")
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
        self.logger(response)
        if not response.startswith("200"):
            raise Exception("Server refused PORT command")
        self.logger(f"Client is listening for data connection at {ip}:10806")
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
            self.logger("Waiting for server to connect")
            data_socket, adr = listen_socket.accept()
            self.logger("Connection completed")
        return data_socket, listen_socket

    def list_files(self):
        listen_socket = None
        data_socket, listen_socket = self.get_data_socket("LIST")
        data_socket = self.context.wrap_socket(data_socket, session=self.control_socket.session)
        response = self.recv_response()
        self.logger(response)
        if not response.startswith("150"):
            data_socket.close()
            return
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
        self.logger(f"Change directory on server '{directory}'")
        self.send_command(f"CWD {directory}")
        response = self.recv_response()
        self.logger(response)

    def change_directory_local(self, directory):
        try:
            if os.path.exists(directory) and os.path.isdir(directory):
                self.logger(f"Local directory set to: {os.path.abspath(directory)}")
            else:
                self.logger(f"Local directory '{directory}' is not available")
        except Exception as e:
            self.logger(f"Error when setting local directory: {e}")

    def print_current_server_directory(self):
        self.send_command("PWD")
        response = self.recv_response()
        self.logger(response)

    def make_directory(self, directory_name):
        self.logger(f"Creating directory {directory_name}")
        self.send_command(f"MKD {directory_name}")
        response = self.recv_response()
        self.logger(response)

    def remove_server_directory(self, directory_name):
        self.logger(f"Removing directory {directory_name}")
        self.send_command(f"RMD {directory_name}")
        response = self.recv_response()
        self.logger(response)
        
    def remove_local_directory(self, directory_name):
        try:
            shutil.rmtree(directory_name)
        except FileNotFoundError:
            print("Folder not exist")
        except PermissionError:
            print("You don't have permission to delete this!")

    def delete_server_file(self, file_name):
        self.logger(f"Deleting file {file_name}")
        self.send_command(f"DELE {file_name}")
        response = self.recv_response()
        self.logger(response)
        
    def delete_local_file(self, file_name):
        try:
            os.remove(file_name)
        except FileNotFoundError:
            self.logger("File not exist")
        except PermissionError:
            self.logger("You don't have permission to delete this!")

    def rename_server_file(self, original_name, new_name):
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
        try:
            self.send_command(f"SIZE {filename}")
            response = self.recv_response()
            if response.startswith("213"):
                return int(response.split(" ")[1])
            return -1
        except Exception:
            return -1

    def scan_file_with_ClamAVAgent(self, filename):
        self.logger(f"Scanning {filename} with ClamAVAgent")
        clamav_host = "127.0.0.1"
        clamav_port = 15116
        agent_process = None
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            clamav_agent_path = os.path.join(script_dir, "clamav_agent.py")
            cmd = [sys.executable, clamav_agent_path]
            agent_process = sp.Popen(cmd, text=True)
            time.sleep(3)
            agent_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            filesize = os.path.getsize(filename)
            filesize_mb = os.path.getsize(filename) / (1024 * 1024)
            agent_socket.settimeout(45 + filesize_mb * 4)
            agent_socket.connect((clamav_host, clamav_port))
            agent_socket.send(f"{filename}<SEPARATOR>{filesize}".encode())
            if self.gui:
                progress = ProgressCallback(self.gui, filesize, "Uploading file to ClamAV Agent")
            else:
                progress = tqdm(total=filesize, unit='B', unit_scale=1024, desc="Uploading file to ClamAV Agent")
            
            with open(filename, "rb") as file:
                while True:
                    data = file.read(4096)
                    if not data:
                        break
                    agent_socket.sendall(data)
                    progress.update(len(data))
            
            if self.gui:
                progress.close()
            else:
                progress.close()
            result = agent_socket.recv(4096).decode()
            agent_socket.close()
            if result == "CLEAN":
                return True
            else:
                return False
        except Exception as e:
            self.logger(f"Unexpected error with agent: {e}")
            return False
        finally:
            if agent_process:
                agent_process.terminate()

    def put_file(self, local_filename, server_filename = None):
        if not os.path.exists(local_filename):
            self.logger(f"File {local_filename} does not exist")
            return
        if not self.scan_file_with_ClamAVAgent(local_filename):
            self.logger("This file is not safe")
            return
        if not server_filename:
            server_filename = os.path.basename(local_filename)
        listen_socket = None
        try:
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
            if self.gui:
                progress = ProgressCallback(self.gui, filesize, "Uploading to server")
            else:
                progress = tqdm(total=filesize, unit='B', unit_scale=1024, desc="Uploading to server")
            
            with open(local_filename, 'rb') as file:
                while True:
                    data = file.read(4096)
                    if not data:
                        break
                    data_socket.sendall(data)
                    progress.update(len(data))
            
            if self.gui:
                progress.close()
            else:
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
        if not os.path.exists(local_folder):
            self.logger(f"Folder {local_folder} does not exist")
            return
        if not server_folder:
            server_folder = os.path.basename(local_folder)
        try:
            self.make_directory(server_folder)
            self.change_directory_server(server_folder)
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
        if not local_filename:
            local_filename = server_filename
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
            if self.gui and filesize != -1:
                progress = ProgressCallback(self.gui, filesize, "Downloading file to local")
            else:
                progress = tqdm(total=filesize if filesize != -1 else None, unit='B', unit_scale=1024, desc="Downloading file to local")
            
            with open(local_filename, 'wb') as file:
                while True:
                    data = data_socket.recv(4096)
                    if not data:
                        break
                    file.write(data)
                    progress.update(len(data))
            
            if self.gui and filesize != -1:
                progress.close()
            else:
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
        if not local_folder:
            local_folder = server_folder
        try:
            os.makedirs(local_folder, exist_ok=True)
        except Exception as e:
            self.logger(f"Error creating directory {local_folder}: {e}")
            return
        current_local_dir = os.getcwd()
        try:
            self.change_directory_server(server_folder)
            os.chdir(local_folder)
            list_file = self.list_files()
            if list_file:
                for line in list_file.splitlines():
                    if line.strip() and len(line.split()) >= 9:
                        parts = line.split()
                        name = " ".join(parts[8:])
                        item_type = "Folder" if parts[0].startswith('d') else "File"
                        if name in [".", ".."]:
                            continue
                        if item_type == "File":
                            self.down_file(name)
                        else:
                            self.down_folder(name)
            self.change_directory_server("..")
        except Exception as e:
            self.logger(f"Error downloading folder {server_folder}: {e}")
        finally:
            try:
                os.chdir(current_local_dir)
            except:
                pass

    def set_transfer_mode(self, mode_sign):
        mode_sign = mode_sign.upper()
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
        self.logger("\n--- Current Status ---")
        self.send_command("STAT")
        response = self.recv_response()
        self.logger(response)

    def close(self):
        if self.control_socket:
            self.send_command("QUIT")
            response = self.recv_response()
            self.logger(response)
            self.control_socket.close()
            self.logger("Connection has been closed")

class GUI(ctk.CTk):
    def __init__(self):
        super().__init__()
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
        self.create()
        self.after(100, self.process_log_queue)

    def create(self):
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
        self.help_button = ctk.CTkButton(self.option_frame, text="Help", fg_color="pink", text_color="#969289", hover_color="#824569", width=100, corner_radius=40, command=self.show_help)
        self.help_button.pack(side="right", padx=5, pady=5)
        self.transferMode_button = ctk.CTkButton(self.option_frame, text = "Transfer mode: Binary", width=100, corner_radius=40, command=self.change_transferMode)
        self.transferMode_button.pack(side = "left", padx=5, pady =5)

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
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Custom.Treeview", background="#2b2b2b", foreground="white", rowheight=25, fieldbackground="#2b2b2b")
        style.map('Custom.Treeview', background=[('selected', '#1f6aa5')])
        style.configure("Custom.Treeview.Heading", background="#565b5e", foreground="white", relief="flat")
        style.map("Custom.Treeview.Heading", background=[('active', '#343638')])
        return style

    def option_menu(self):
        self.local_menu = tk.Menu(self, tearoff=0, bg="#2b2b2b", fg="white")
        self.local_menu.add_command(label="Upload", command=self.upload_selected)
        self.local_menu.add_command(label="Delete", command=self.delete_selected_local)
        self.local_menu.add_command(label="Rename", command=self.rename_selected_local)
        self.remote_menu = tk.Menu(self, tearoff=0, bg="#2b2b2b", fg="white")
        self.remote_menu.add_command(label="Download", command=self.download_selected)
        self.remote_menu.add_command(label="Delete", command=self.delete_selected_remote)
        self.remote_menu.add_command(label="Rename", command=self.rename_selected_remote)

    def show_local_menu(self, event):
        self.local_tree.identify_row(event.y)
        if self.local_tree.selection():
            self.local_menu.post(event.x_root, event.y_root)

    def show_remote_menu(self, event):
        self.remote_tree.identify_row(event.y)
        if self.remote_tree.selection():
            self.remote_menu.post(event.x_root, event.y_root)

    def switch_mode(self):
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
        self.log_queue.put(message)

    def process_log_queue(self):
        try:
            while True:
                message = self.log_queue.get_nowait()
                self.log_box.configure(state="normal")
                self.log_box.insert("end", message + "\n")
                self.log_box.see("end")
                self.log_box.configure(state="disabled")
        except queue.Empty:
            pass
        self.after(100, self.process_log_queue)
    
    def show_progress(self, text, value=0):
        self.progress_label.configure(text=text)
        self.progress_bar.set(value)
        self.progress_frame.grid(row=1, column=0, sticky="ew", pady=(5,0))
        self.update()
    
    def update_progress(self, value):
        self.progress_bar.set(value)
        self.update()
    
    def hide_progress(self):
        self.progress_frame.grid_remove()
        self.progress_label.configure(text="")
        self.update()

    def refresh_remote_files(self):
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
        if self.client and self.client.control_socket:
            threading.Thread(target=self.disconnect, daemon=True).start()
        else:
            threading.Thread(target=self.connect, daemon=True).start()

    def connect(self):
        host = self.host_entry.get()
        port = self.port_entry.get()
        username = self.username_entry.get()
        password = self.pass_entry.get()
        if True:
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

    def disconnect(self):
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

    def refresh(self):
        if self.client and self.client.control_socket:
            self.refresh_remote_files()
            self.refresh_local_files()

    def show_status(self):
        if self.client and self.client.control_socket:
            self.client.show_status()

    def change_local_dir(self):
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
        if self.client and self.client.control_socket:
            dialog = ctk.CTkInputDialog(text="Enter your new directory path", title="Change server directory")
            self.client.change_directory_server(dialog.get_input())
            self.refresh_remote_files()
            
    def show_server_dir(self):
        if self.client and self.client.control_socket:
            self.client.print_current_server_directory()

    def change_transferMode(self):
        if self.client and self.client.control_socket:
            if self.transferMode_button._text == "Transfer mode: Binary":
                self.client.set_transfer_mode('A')
                self.transferMode_button.configure(text = "Transfer mode: ASCII")
            else:
                self.client.set_transfer_mode('I')
                self.transferMode_button.configure(text = "Transfer mode: Binary")


    def upload_selected(self):
        selected_items = self.local_tree.selection()
        for item in selected_items:
            iname = self.local_tree.item(item, "text")
            itype = self.local_tree.item(item, "values")[1] 
            full_path = os.path.join(self.local_path, iname)
            if itype == "Folder":
                thread = threading.Thread(target=self.client.put_folder, args=(full_path,), daemon=True)
                thread.start()
            else:
                thread = threading.Thread(target=self.client.put_file, args=(full_path,), daemon=True)
                thread.start()
                
    def delete_selected_local(self):
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
        selected_items = self.remote_tree.selection()
        for item in selected_items:
            iname = self.remote_tree.item(item, "text")
            itype = self.remote_tree.item(item, "values")[1] 
            if itype == "Folder":
                thread = threading.Thread(target=self.client.down_folder, args=(iname,), daemon=True)
                thread.start()
                self.log("Download complete")
            else:
                thread = threading.Thread(target=self.client.down_file, args=(iname,), daemon=True)
                thread.start()
                self.log("Download complete")
    
    def delete_selected_remote(self):
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
    app.mainloop()