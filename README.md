# SocketProgramming
# Secure FTP Client with ClamAV Integration
## :pushpin: Overview
This project is a Secure FTP Client written in Python with a modern GUI (using CustomTkinter) that supports TLS-encrypted FTP connections, file and folder management, and automatic virus scanning using ClamAV before uploads. It provides a dual-panel interface for browsing local and remote directories, making it easy to transfer files securely while ensuring malware detection.
The client integrates with a lightweight ClamAV agent (running locally) to scan files prior to upload, adding an extra layer of security. This is ideal for users who need a simple, secure FTP tool with built-in antivirus checks.
Note: This project focuses on socket programming and FTPS (FTP over TLS). TLS certificate verification is disabled for demonstration purposes (to allow connections to servers without proper certs, like some FileZilla setups). In production, enable verification for security.

---
## :sparkles: Features

- **Secure Connection (FTPS)**: Supports AUTH TLS for encrypted control and data channels.
- **Dual-Panel File Browser**: View and manage local and server directories side-by-side.
- **File & Folder Management**: Upload, download, delete, rename, and create directories on both local and remote sides.
Recursive Transfers: Upload/download entire folders with progress tracking.
- **ClamAV Integration**: Automatically scans files for viruses before uploading; uses a local agent for efficient scanning.
Passive/Active Mode Switching: Easily toggle between FTP modes to handle different network setups.
- **Progress Tracking**: Real-time progress bars for scans, uploads, and downloads (works in GUI and CLI).
- **Multi-Selection Support**: Use Ctrl+Click to select multiple files/folders for operations.
- **Help System**: Built-in help window with usage instructions.

---
# :open_file_folder: Project Structure
**The project consists of the following key files:**

- `ftp_client.py`: The main FTP client script with GUI implementation using CustomTkinter. Handles connections, file transfers, and user interactions.
- `clamav_agent.py`: A local server agent that listens on `127.0.0.1:15116` for file scan requests, uses clamscan to check for malware, and returns results ("CLEAN", "INFECTED", or "ERROR").
- `README.md`: This documentation file.

Temporary directories (e.g., scan_temp_dir) are created during runtime for file handling and cleaned up automatically.

---
# :hammer: Requirements
## Software Dependencies

- **Python 3.8+**: The client is built in Python.
- **ClamAV**: Required for virus scanning. Install the ClamAV daemon and command-line tools (`clamscan` must be in your PATH).

    - On Ubuntu/Debian: `sudo apt update && sudo apt install clamav clamav-daemon`
    - On macOS (via Homebrew): `brew install clamav`
    - On Windows: Download from [official site](https://www.clamav.net/downloads) and add to PATH.
    - After installation, update the virus database: `freshclam` (run as admin/root if needed).


- **Python Libraries**:

    - `customtkinter`: For the modern GUI.
    - `tqdm`: For progress bars.
    - `tkinter`: Built-in, but ensure it's installed (comes with Python).
    - Other standard libraries: `socket`, `ssl`, `os`, `shutil`, `subprocess`, `threading`, `queue`.



## Hardware/Network

- A running FTP server (e.g., FileZilla Server) that supports FTPS.
- Localhost access for the ClamAV agent (runs on loopback interface).

---
# :rocket: Installation

1. **Clone the Repository**:
```text
git clone <repository-url>
cd <repository-directory>
```
2. **Install Python Dependencies**: Use pip to install required libraries:
```text
pip install customtkinter tqdm
```

3. **Install ClamAV**: Follow the instructions in the Requirements section. Ensure ``clamscan`` works by running:
```text
clamscan --version
```
Update the database:
```text
freshclam
```

4. **Verify Setup**:

- Run ``python clamav_agent.py`` manually to test the agent (it should listen on port 15116).
- The client will auto-start the agent if it's not running.
---
# :book: Usage
## Running the Application

1. **Start the GUI client**:
```text
python ftp_client.py
```
- The ClamAV agent will launch automatically as a subprocess if not already running.
- A window will open with fields for server IP, port (default: 21), username, and password.


2. **Connecting to the Server**:

- Enter server details.
- Choose Passive (default) or Active mode.
- Click **Connect**.
- The left panel shows local files; the right panel shows server files.


3. **File Operations**:

- **Upload**: Select local files/folders (Ctrl+Click for multiple), right-click > Upload (or use button).

    - Files are scanned with ClamAV before upload. If infected, upload is aborted.
- **Download**: Select remote files/folders, right-click > Download (or use button).
- **Delete/Rename**: Right-click on items in local or remote panels.
- **Create Directory**: Use buttons for local/server.
- **Refresh**: Update file lists after operations.
- **Transfer Mode**: Toggle between Binary (default) and ASCII.


4. **Scanning Process**:

- Before any upload, files are sent to the local ClamAV agent for scanning.
- Progress is shown via a bar.
- Results: CLEAN (proceed), INFECTED (abort), ERROR (abort with log).


5. **Help & Status**:

- Click **Help** for a popup with instructions.
- Logs appear in the bottom panel for all actions.


6. Disconnect & Exit:

- Click Disconnect to close the FTP session.
- Closing the window auto-kills the ClamAV agent.



## Command-Line Mode (Limited)
While the project is GUI-focused, progress callbacks support CLI output via `tqdm`. Run transfers programmatically by instantiating `ClientSocket` and calling methods like `put_file()`.

---

# :gear: Configuration

- **ClamAV Agent**:

    - Host/Port: Hardcoded to `127.0.0.1:15116` (edit in `clamav_agent.py` if needed).
    - Temp Directory: `scan_temp_dir` (auto-created and cleaned).


- FTP Client:
    - Transfer Mode: Default Binary ('I'); toggle via GUI or `set_transfer_mode()`.
    - Socket Timeout: 30 seconds (editable in code).
    - Active Mode Port: Fixed at 10806 (edit in `active_mode()` if conflicts occur).

---
# :bug:Troubleshooting

- **ClamAV Not Found**: Ensure `clamscan` is in PATH. Install ClamAV and run `freshclam`.
- **Connection Errors**: Check firewall (allow port 21 and data ports). Try switching Passive/Active mode.
- **Scan Errors**: If agent fails to start, run `python clamav_agent.py` manually and check output.
- **TLS Issues**: Verification is disabled; for secure use, enable `context.check_hostname = True` and `context.verify_mode = ssl.CERT_REQUIRED` in `login()`.
- **Progress Bar Issues**: Ensure `tqdm` is installed.
- **Permissions**: Run as admin if deleting system-protected files.

If issues persist, check console logs or open an issue.

---

# :handshake: Contributing
Contributions are welcome! Fork the repo, make changes, and submit a pull request. Focus areas:
- Add support for more FTP commands.
- Improve error handling.
- Enhance GUI themes.
---
# :pray: Acknowledgments

- Uses [ClamAV](https://www.clamav.net/downloads) for antivirus scanning.
- Inspired by socket programming tutorials and secure FTP needs.

For questions, contact: [truongtandung1511@gmail.com][kinhquocne@gmail.com].
