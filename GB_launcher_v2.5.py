import ctypes
from ctypes import wintypes
import os
import sys
from Crypto.Cipher import AES
import binascii
import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import configparser
import time
import shutil
import requests

# Define STARTUPINFOW manually
class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]

# Define PROCESS_INFORMATION manually
class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]

def read_launcher_ini():
    """Read configuration from Launcher.ini, including patch settings."""
    config = configparser.ConfigParser()
    config['DEFAULT'] = {
        'VERSION': '440',
        'EXIT_IMMEDIATELY': 'TRUE',
        'CREATE_SUSPENDED': 'TRUE'
    }
    config['Credentials'] = {}
    config['PatchOptions'] = {}
    config['PatchStates'] = {}
    
    if os.path.exists("Launcher.ini"):
        config.read("Launcher.ini")
    
    return config

def read_patch_ini():
    """Read patch configuration from Launcher.ini."""
    config = read_launcher_ini()
    patches = []
    section = config['PatchOptions']
    states = config['PatchStates']
    i = 1
    while f"Address{i}" in section:
        try:
            name = section.get(f"Name{i}", f"Patch{i}")
            address = int(section[f"Address{i}"], 16)
            value = section.get(f"Value{i}", "")
            size = int(section.get(f"Size{i}", 19))
            enabled = states.get(f"Patch{i}", "True") == "True"
            patches.append({"NAME": name, "ADDRESS": address, "VALUE": value, "SIZE": size, "ENABLED": enabled})
        except (ValueError, KeyError) as e:
            print(f"Error parsing patch {i}: {e}")
        i += 1
    return patches, config

def save_patch_ini(config):
    """Save patch configuration to Launcher.ini."""
    with open("Launcher.ini", "w") as f:
        config.write(f)

def save_launcher_ini(config):
    """Save configuration to Launcher.ini."""
    with open("Launcher.ini", "w") as f:
        config.write(f)

def find_gunbound_executable(custom_path=""):
    """Find GunBound executable or return None if not found."""
    if custom_path and os.path.exists(custom_path):
        return custom_path
    
    possible_executables = [
        "gunbound.gme",
        "gunbound.exe",
        "GunBound.gme",
        "GunBound.exe"
    ]
    
    for exe in possible_executables:
        exe_path = os.path.join(os.getcwd(), exe)
        if os.path.exists(exe_path):
            return exe_path
    
    return None

def encrypt_credentials(username, password):
    """Encrypt credentials with AES-128 ECB."""
    key = bytes.fromhex("FAEE85F24073D9161390197F6E562A67")
    username = username.ljust(16, "\0").encode("ascii")[:16]
    password = password.ljust(16, "\0").encode("ascii")[:16]
    data = username + password + b"\0" * 16
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(data)
    return binascii.hexlify(encrypted).decode("ascii").upper()

def decrypt_credentials(encrypted):
    """Decrypt credentials with AES-128 ECB."""
    key = bytes.fromhex("FAEE85F24073D9161390197F6E562A67")
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(binascii.unhexlify(encrypted))
    username = decrypted[:16].decode("ascii").rstrip("\0")
    password = decrypted[16:32].decode("ascii").rstrip("\0")
    return username, password

def run_gunbound(credentials, create_suspended=True, gunbound_path=None):
    """Run GunBound with credentials using CreateProcess, return process info."""
    kernel32 = ctypes.WinDLL("kernel32")
    startupinfo = STARTUPINFOW()
    processinfo = PROCESS_INFORMATION()
    cmdline = ctypes.c_wchar_p(credentials)
    creation_flags = 0x00000004 if create_suspended else 0

    if not os.path.exists(gunbound_path):
        return None

    success = kernel32.CreateProcessW(
        gunbound_path,
        cmdline,
        None,
        None,
        False,
        creation_flags,
        None,
        None,
        ctypes.byref(startupinfo),
        ctypes.byref(processinfo)
    )

    if not success:
        return None

    return processinfo

def write_memory_string(handle, address, value, size):
    """Write string to process memory at specified address."""
    try:
        value_bytes = value.encode("ascii")[:size-1] + b"\x00" * (size - len(value.encode("ascii")))
        buffer = ctypes.create_string_buffer(value_bytes)
        bytes_written = ctypes.c_size_t()
        kernel32 = ctypes.WinDLL("kernel32")
        success = kernel32.WriteProcessMemory(
            handle, address, buffer, size, ctypes.byref(bytes_written)
        )
        return success and bytes_written.value == size
    except Exception as e:
        print(f"Error writing memory: {e}")
        return False

def write_file_string(file_path, offset, value, size):
    """Write string to file at specified offset."""
    try:
        value_bytes = value.encode("ascii")[:size-1] + b"\x00" * (size - len(value.encode("ascii")))
        with open(file_path, "r+b") as file:
            file.seek(offset)
            file.write(value_bytes)
            return True
    except Exception as e:
        print(f"Error writing file: {e}")
        return False

def copy_folder_contents(source_folder, dest_folder, delete_graphics_dll=False):
    """Copy contents of source folder to destination folder and optionally delete graphics.dll."""
    try:
        if not os.path.exists(source_folder):
            return False, f"Source folder {source_folder} does not exist"
        
        # Ensure destination folder exists
        os.makedirs(dest_folder, exist_ok=True)
        
        # Copy all files from source to destination
        for item in os.listdir(source_folder):
            src_path = os.path.join(source_folder, item)
            dst_path = os.path.join(dest_folder, item)
            if os.path.isfile(src_path):
                shutil.copy2(src_path, dst_path)
        
        # Delete graphics.dll if specified and it exists
        graphics_path = os.path.join(dest_folder, "graphics.dll")
        if delete_graphics_dll and os.path.exists(graphics_path):
            os.remove(graphics_path)
        
        return True, "Files copied successfully"
    except Exception as e:
        return False, f"Error copying files: {e}"

def check_latest_version():
    """Check the highest valid version for graphics.xfs and avatar.xfs independently starting from v1."""
    base_url = "https://cdn.gunbound.sample.com/prod/launcher/files-update/v{}/"
    files = ["graphics.xfs", "avatar.xfs"]
    latest_versions = {}

    for file in files:
        version = 1
        latest_version = None
        while True:
            version_url = base_url.format(version)
            try:
                response = requests.head(version_url + file, timeout=5, headers={"Cache-Control": "no-cache"})
                if response.status_code == 200:
                    latest_version = version
                    version += 1
                else:
                    break
            except requests.RequestException:
                break
        latest_versions[file] = latest_version if latest_version is not None else None
    
    return latest_versions

def download_files(file_versions, progress_bar, status_label, root):
    """Download graphics.xfs and avatar.xfs for their respective highest versions, skip if file size matches."""
    base_url_template = "https://cdn.gunboud.sample.com/prod/launcher/files-update/v{}/"
    files = ["graphics.xfs", "avatar.xfs"]
    dest_dir = os.getcwd()
    success = True
    error_message = ""
    downloaded_files = []
    
    # Get total size for progress bar
    total_size = 0
    files_to_download = []
    for file in files:
        version = file_versions.get(file)
        if version is None:
            success = False
            error_message = f"Gagal menemukan versi valid untuk {file}"
            break
        base_url = base_url_template.format(version)
        try:
            response = requests.head(base_url + file, timeout=5)
            if response.status_code == 200:
                server_size = int(response.headers.get("Content-Length", 0))
                local_path = os.path.join(dest_dir, file)
                local_size = os.path.getsize(local_path) if os.path.exists(local_path) else -1
                if server_size != local_size:
                    files_to_download.append((file, version))
                    total_size += server_size
                else:
                    status_label.config(text=f"Status: Melewati {file}: ukuran sama di v{version}")
                    root.update()
            else:
                success = False
                error_message = f"Gagal memeriksa {file} di versi v{version}: Status {response.status_code}"
                break
        except requests.RequestException as e:
            success = False
            error_message = f"Gagal memeriksa {file} di versi v{version}: {str(e)}"
            break
        except OSError as e:
            files_to_download.append((file, version))
            total_size += server_size
    
    if not success or not files_to_download:
        if success and not files_to_download:
            return True, "Tidak ada file yang perlu diupdate"
        return False, error_message
    
    # Initialize progress bar
    progress_bar["maximum"] = total_size
    progress_bar["value"] = 0
    downloaded_size = 0
    
    for file, version in files_to_download:
        base_url = base_url_template.format(version)
        try:
            response = requests.get(base_url + file, stream=True, timeout=10)
            if response.status_code == 200:
                file_path = os.path.join(dest_dir, file)
                status_label.config(text=f"Status: Mendownload {file} dari v{version}...")
                root.update()
                with open(file_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            downloaded_size += len(chunk)
                            progress_bar["value"] = downloaded_size
                            root.update()
                downloaded_files.append(f"{file} (v{version})")
            else:
                success = False
                error_message = f"Gagal mendownload {file} dari versi v{version}: Status {response.status_code}"
                break
        except requests.RequestException as e:
            success = False
            error_message = f"Gagal mendownload {file} dari versi v{version}: {str(e)}"
            break
    
    progress_bar["value"] = 0  # Reset progress bar
    if success:
        return True, f"Berhasil mendownload {', '.join(downloaded_files)}"
    return False, error_message

class GunBoundLauncherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("GunBound Launcher")
        self.root.geometry("380x687")
        self.root.configure(bg="#2b2b2b")

        # Set modern ttk theme
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", font=("Helvetica", 10), padding=6, background="#3c3f41", foreground="#ffffff", bordercolor="#555555")
        style.map("TButton", background=[('active', '#4a4d50')])
        style.configure("TCombobox", font=("Helvetica", 10), padding=5, fieldbackground="#3c3f41", background="#3c3f41", foreground="#ffffff")
        style.configure("TEntry", font=("Helvetica", 10), padding=5, fieldbackground="#3c3f41", foreground="#ffffff")
        style.configure("TCheckbutton", font=("Helvetica", 9), background="#2b2b2b", foreground="#ffffff")
        style.map("TCheckbutton", background=[('active', '#2b2b2b')])
        style.configure("TRadiobutton", font=("Helvetica", 10), background="#2b2b2b", foreground="#ffffff")
        style.map("TRadiobutton", background=[('active', '#2b2b2b')])
        style.configure("TProgressbar", thickness=20)

        self.process_info = None
        self.config = read_launcher_ini()
        self.patches, self.patch_config = read_patch_ini()
        self.create_suspended = self.config['DEFAULT'].getboolean('CREATE_SUSPENDED', True)
        self.exit_immediately = self.config['DEFAULT'].getboolean('EXIT_IMMEDIATELY', True)
        
        # Main container
        main_frame = tk.Frame(self.root, bg="#2b2b2b", padx=15, pady=15)
        main_frame.pack(fill="both", expand=True)
        
        # Executable Path Section
        exe_frame = tk.Frame(main_frame, bg="#2b2b2b")
        exe_frame.pack(fill="x", pady=5)
        tk.Label(exe_frame, text="Gunbound exe/gme Path:", font=("Helvetica", 10), fg="#cccccc", bg="#2b2b2b").pack(anchor="w")
        self.exe_entry = ttk.Entry(exe_frame)
        self.exe_entry.pack(fill="x", pady=5)
        ttk.Button(exe_frame, text="Browse", command=self.browse_exe).pack(pady=5)
        
        # Account Section
        account_frame = tk.Frame(main_frame, bg="#2b2b2b")
        account_frame.pack(fill="x", pady=10)
        tk.Label(account_frame, text="Account Settings:", font=("Helvetica", 10, "bold"), fg="#ffffff", bg="#2b2b2b").pack(anchor="w")
        self.account_var = tk.StringVar()
        self.accounts = [(k, v) for k, v in self.config['Credentials'].items() if k not in self.config['DEFAULT']]
        account_names = [k for k, _ in self.accounts] or ["No accounts saved"]
        self.account_dropdown = ttk.Combobox(account_frame, textvariable=self.account_var, values=account_names, state="readonly")
        self.account_dropdown.pack(fill="x", pady=5)
        self.account_dropdown.set(account_names[0])
        
        tk.Label(account_frame, text="Username:", font=("Helvetica", 10), fg="#cccccc", bg="#2b2b2b").pack(anchor="w")
        self.username_entry = ttk.Entry(account_frame)
        self.username_entry.pack(fill="x", pady=5)
        
        tk.Label(account_frame, text="Password:", font=("Helvetica", 10), fg="#cccccc", bg="#2b2b2b").pack(anchor="w")
        self.password_entry = ttk.Entry(account_frame, show="*")
        self.password_entry.pack(fill="x", pady=5)
        
        # Patch Options Section
        patch_frame = tk.Frame(main_frame, bg="#2b2b2b")
        patch_frame.pack(fill="x", pady=10)
        tk.Label(patch_frame, text="Patch Options:", font=("Helvetica", 10, "bold"), fg="#ffffff", bg="#2b2b2b").pack(anchor="w")
        
        # Patch Dropdown
        self.patch_var = tk.StringVar()
        patched_names = [p["NAME"] for p in self.patches] or ["No patches available"]
        self.patch_dropdown = ttk.Combobox(patch_frame, textvariable=self.patch_var, values=patched_names, state="readonly")
        self.patch_dropdown.pack(fill="x", pady=5)
        self.patch_dropdown.set(patched_names[0])
        
        # Patch Details Frame
        self.patch_details_frame = tk.Frame(patch_frame, bg="#2b2b2b")
        self.patch_details_frame.pack(fill="x", pady=5)
        
        # Patch Enable Checkbox
        self.patch_enabled_var = tk.BooleanVar()
        self.patch_enabled_check = ttk.Checkbutton(self.patch_details_frame, text="Enable Patch", variable=self.patch_enabled_var, command=self.toggle_patch)
        self.patch_enabled_check.pack(anchor="w")
        
        # Bind dropdown selection
        self.patch_dropdown.bind("<<ComboboxSelected>>", self.load_patch_details)
        if patched_names[0] != "No patches available":
            self.load_patch_details(None)
        
        # Action Buttons Section (2x4 grid to accommodate Display and Update buttons)
        action_frame = tk.Frame(main_frame, bg="#2b2b2b")
        action_frame.pack(fill="x", pady=10)
        tk.Label(action_frame, text="Actions:", font=("Helvetica", 10, "bold"), fg="#ffffff", bg="#2b2b2b").pack(anchor="w")
        
        button_grid = tk.Frame(action_frame, bg="#2b2b2b")
        button_grid.pack(fill="x")
        
        ttk.Button(button_grid, text="Launch", command=self.launch).grid(row=0, column=0, padx=4, pady=4, sticky="ew")
        ttk.Button(button_grid, text="Start Suspend", command=self.launch_suspended).grid(row=1, column=0, padx=4, pady=4, sticky="ew")
        ttk.Button(button_grid, text="Resume", command=self.resume_process).grid(row=2, column=0, padx=4, pady=4, sticky="ew")
        ttk.Button(button_grid, text="Save Account", command=self.save_account).grid(row=0, column=1, padx=4, pady=4, sticky="ew")
        ttk.Button(button_grid, text="Delete Account", command=self.delete_account).grid(row=1, column=1, padx=4, pady=4, sticky="ew")
        ttk.Button(button_grid, text="Terminate", command=self.terminate_process).grid(row=2, column=1, padx=4, pady=4, sticky="ew")
        ttk.Button(button_grid, text="Display", command=self.open_display_window).grid(row=0, column=2, padx=4, pady=4, sticky="ew")
        ttk.Button(button_grid, text="Check Update", command=self.update_files).grid(row=1, column=2, padx=4, pady=4, sticky="ew")
        
        button_grid.columnconfigure(0, weight=1)
        button_grid.columnconfigure(1, weight=1)
        button_grid.columnconfigure(2, weight=1)
        button_grid.columnconfigure(3, weight=1)
        
        # Status Label
        self.status_label = tk.Label(main_frame, text="Status: Ready", font=("Helvetica", 9), fg="#00cc00", bg="#2b2b2b", anchor="w")
        self.status_label.pack(fill="x", pady=5)
        
        # Progress Bar
        self.progress_bar = ttk.Progressbar(main_frame, orient="horizontal", mode="determinate")
        self.progress_bar.pack(fill="x", pady=5)
        
        # Footer
        tk.Label(main_frame, text="Copyright by Firelordz", font=("Helvetica", 8, "italic"), fg="#666666", bg="#2b2b2b").pack(side="bottom", pady=5)
        
        self.account_dropdown.bind("<<ComboboxSelected>>", self.load_account)
    
    def browse_exe(self):
        """Open file dialog to select GunBound executable."""
        file_path = filedialog.askopenfilename(
            title="Select GunBound Executable",
            filetypes=[("Executable files", "*.exe *.gme"), ("All files", "*.*")]
        )
        if file_path:
            self.exe_entry.delete(0, tk.END)
            self.exe_entry.insert(0, file_path)
    
    def load_account(self, event):
        """Load selected account credentials."""
        selected = self.account_var.get()
        if selected == "No accounts saved":
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
            return
        
        for account_name, encrypted in self.accounts:
            if account_name == selected:
                username, password = decrypt_credentials(encrypted)
                self.username_entry.delete(0, tk.END)
                self.username_entry.insert(0, username)
                self.password_entry.delete(0, tk.END)
                self.password_entry.insert(0, password)
                break
    
    def save_account(self):
        """Save new account credentials."""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            messagebox.showerror("Error", "Username or password cannot be empty!")
            return
        
        encrypted = encrypt_credentials(username, password)
        self.config['Credentials'][username] = encrypted
        save_launcher_ini(self.config)
        
        self.accounts = [(k, v) for k, v in self.config['Credentials'].items() if k not in self.config['DEFAULT']]
        account_names = [k for k, _ in self.accounts] or ["No accounts saved"]
        self.account_dropdown['values'] = account_names
        self.account_dropdown.set(username)
        messagebox.showinfo("Success", "Account saved successfully!")
    
    def delete_account(self):
        """Delete selected account."""
        selected = self.account_var.get()
        if selected == "No accounts saved":
            messagebox.showerror("Error", "No account selected!")
            return
        
        if selected in self.config['Credentials']:
            del self.config['Credentials'][selected]
            save_launcher_ini(self.config)
            self.accounts = [(k, v) for k, v in self.config['Credentials'].items() if k not in self.config['DEFAULT']]
            account_names = [k for k, _ in self.accounts] or ["No accounts saved"]
            self.account_dropdown['values'] = account_names
            self.account_dropdown.set(account_names[0])
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
            messagebox.showinfo("Success", "Account deleted successfully!")
    
    def load_patch_details(self, event):
        """Load selected patch details into the UI."""
        selected = self.patch_var.get()
        if selected == "No patches available":
            self.patch_enabled_var.set(False)
            return
        
        for i, patch in enumerate(self.patches):
            if patch["NAME"] == selected:
                self.patch_enabled_var.set(patch["ENABLED"])
                break
    
    def toggle_patch(self):
        """Toggle patch enable/disable state and save to config."""
        selected = self.patch_var.get()
        if selected == "No patches available":
            return
        
        for i, patch in enumerate(self.patches):
            if patch["NAME"] == selected:
                patch["ENABLED"] = self.patch_enabled_var.get()
                self.patch_config['PatchStates'][f"Patch{i+1}"] = str(self.patch_enabled_var.get())
                save_patch_ini(self.patch_config)
                break
    
    def apply_patches(self, hProcess, file_path=None):
        """Apply enabled memory patches from Launcher.ini, fallback to file patching if memory fails."""
        patches = [p for p in self.patches if p["ENABLED"]]
        if not patches:
            self.status_label.config(text="Status: No enabled patches found in Launcher.ini")
            return False
        
        memory_success = True
        success_count = 0
        for i, patch in enumerate(patches, 1):
            address = patch["ADDRESS"]
            value = patch["VALUE"]
            size = patch["SIZE"]
            self.status_label.config(text=f"Status: Patching {patch['NAME']} at {hex(address)}")
            self.root.update()
            if write_memory_string(hProcess, address, value, size):
                success_count += 1
            else:
                memory_success = False
                self.status_label.config(text=f"Status: Failed to patch {patch['NAME']} at {hex(address)}")
                self.root.update()
                time.sleep(1)
                if file_path:
                    self.status_label.config(text=f"Status: Falling back to file patching for {patch['NAME']}")
                    self.root.update()
                    if write_file_string(file_path, address, value, size):
                        self.status_label.config(text=f"Status: File patched for {patch['NAME']} at offset {hex(address)}")
                        success_count += 1
                    else:
                        self.status_label.config(text=f"Status: Failed to patch file for {patch['NAME']} at offset {hex(address)}")
                        self.root.update()
                        time.sleep(1)
        
        status = f"Status: Applied {success_count}/{len(patches)} patches successfully"
        self.status_label.config(text=status)
        return memory_success and success_count == len(patches)
    
    def open_display_window(self):
        """Open a new window with display mode options using radio buttons."""
        display_window = tk.Toplevel(self.root)
        display_window.title("Display Options")
        display_window.geometry("400x300")
        display_window.configure(bg="#2b2b2b")
        
        # Display Options Frame
        display_frame = tk.Frame(display_window, bg="#2b2b2b", padx=15, pady=15)
        display_frame.pack(fill="both", expand=True)
        
        # Radio Button Selection
        self.display_mode_var = tk.StringVar(value="voodoo2")  # Default selection
        ttk.Radiobutton(display_frame, text="Full Screen Voodoo2", value="voodoo2", variable=self.display_mode_var).pack(anchor="w", pady=5)
        ttk.Radiobutton(display_frame, text="Full Screen DXwnd", value="dxwnd", variable=self.display_mode_var).pack(anchor="w", pady=5)
        ttk.Radiobutton(display_frame, text="Full Screen Compat", value="compat", variable=self.display_mode_var).pack(anchor="w", pady=5)
        ttk.Radiobutton(display_frame, text="Windowed", value="windowed", variable=self.display_mode_var).pack(anchor="w", pady=5)
        
        # OK Button
        ttk.Button(display_frame, text="OK", command=lambda: self.apply_display_mode(display_window)).pack(fill="x", pady=10)
    
    def apply_display_mode(self, display_window):
        """Apply the selected display mode and close the window."""
        mode = self.display_mode_var.get()
        if mode == "voodoo2":
            self.set_voodoo2_mode()
        elif mode == "dxwnd":
            self.set_dxwnd_mode()
        elif mode == "compat":
            self.set_compat_mode()
        elif mode == "windowed":
            self.set_windowed_mode()
        display_window.destroy()
    
    def set_voodoo2_mode(self):
        """Copy contents of .\compat\1 to launcher directory, delete graphics.dll."""
        success, message = copy_folder_contents(
            source_folder=os.path.join(os.getcwd(), "compat", "1"),
            dest_folder=os.getcwd(),
            delete_graphics_dll=True
        )
        if success:
            messagebox.showinfo("Success", "Full Screen Voodoo2 mode set successfully.")
            self.status_label.config(text="Status: Full Screen Voodoo2 mode set")
        else:
            messagebox.showerror("Error", message)
            self.status_label.config(text=f"Status: {message}")
    
    def set_dxwnd_mode(self):
        """Copy contents of .\compat\2 to launcher directory, preserve graphics.dll."""
        success, message = copy_folder_contents(
            source_folder=os.path.join(os.getcwd(), "compat", "2"),
            dest_folder=os.getcwd(),
            delete_graphics_dll=False
        )
        if success:
            messagebox.showinfo("Success", "Full Screen DXwnd mode set successfully.")
            self.status_label.config(text="Status: Full Screen DXwnd mode set")
        else:
            messagebox.showerror("Error", message)
            self.status_label.config(text=f"Status: {message}")
    
    def set_compat_mode(self):
        """Copy contents of .\compat\4 to launcher directory, delete graphics.dll."""
        success, message = copy_folder_contents(
            source_folder=os.path.join(os.getcwd(), "compat", "4"),
            dest_folder=os.getcwd(),
            delete_graphics_dll=True
        )
        if success:
            messagebox.showinfo("Success", "Full Screen Compat mode set successfully.")
            self.status_label.config(text="Status: Full Screen Compat mode set")
        else:
            messagebox.showerror("Error", message)
            self.status_label.config(text=f"Status: {message}")
    
    def set_windowed_mode(self):
        """Copy contents of .\compat\3 to launcher directory, delete graphics.dll."""
        success, message = copy_folder_contents(
            source_folder=os.path.join(os.getcwd(), "compat", "3"),
            dest_folder=os.getcwd(),
            delete_graphics_dll=True
        )
        if success:
            messagebox.showinfo("Success", "Windowed mode set successfully.")
            self.status_label.config(text="Status: Windowed mode set")
        else:
            messagebox.showerror("Error", message)
            self.status_label.config(text=f"Status: {message}")
    
    def update_files(self):
        """Check and download the latest graphics.xfs and avatar.xfs files."""
        self.status_label.config(text="Status: Mengecek versi terbaru...")
        self.progress_bar["value"] = 0
        self.root.update()
        
        file_versions = check_latest_version()
        if not file_versions["graphics.xfs"] or not file_versions["avatar.xfs"]:
            missing_files = [f for f, v in file_versions.items() if v is None]
            messagebox.showerror("Error", f"Gagal menemukan versi valid untuk {', '.join(missing_files)}")
            self.status_label.config(text=f"Status: Gagal menemukan versi valid untuk {', '.join(missing_files)}")
            self.progress_bar["value"] = 0
            return
        
        self.status_label.config(text=f"Status: Mengecek file graphics.xfs (v{file_versions['graphics.xfs']}) dan avatar.xfs (v{file_versions['avatar.xfs']})...")
        self.root.update()
        
        success, message = download_files(file_versions, self.progress_bar, self.status_label, self.root)
        if success:
            messagebox.showinfo("Success", message)
            self.status_label.config(text=f"Status: {message}")
        else:
            messagebox.showerror("Error", message)
            self.status_label.config(text=f"Status: {message}")
        self.progress_bar["value"] = 0
    
    def launch(self):
        """Launch GunBound with selected credentials and apply patches."""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            messagebox.showerror("Error", "Username or password cannot be empty!")
            return
        
        credentials = encrypt_credentials(username, password)
        gunbound_path = find_gunbound_executable(self.exe_entry.get().strip())
        if not gunbound_path:
            messagebox.showerror("Error", "No valid GunBound executable found! Please specify a valid path or ensure gunbound.exe/gme is in the directory.")
            return
        
        self.status_label.config(text="Status: Launching GunBound in suspended state...")
        self.root.update()
        self.process_info = run_gunbound(credentials, True, gunbound_path)
        
        if not self.process_info:
            messagebox.showerror("Error", f"Failed to start GunBound: {ctypes.GetLastError()}")
            self.status_label.config(text="Status: Failed to launch GunBound")
            return
        
        if self.apply_patches(self.process_info.hProcess, gunbound_path):
            self.status_label.config(text="Status: Patches applied successfully")
        else:
            self.status_label.config(text="Status: Some patches failed, attempted file patching")
        
        kernel32 = ctypes.WinDLL("kernel32")
        if kernel32.ResumeThread(self.process_info.hThread) == -1:
            messagebox.showerror("Error", f"Failed to resume process: {ctypes.GetLastError()}")
            self.status_label.config(text="Status: Failed to resume process")
        else:
            self.status_label.config(text="Status: Process resumed")
        
        if self.exit_immediately:
            kernel32.CloseHandle(self.process_info.hThread)
            kernel32.CloseHandle(self.process_info.hProcess)
            self.root.quit()
    
    def launch_suspended(self):
        """Launch GunBound in suspended state and apply patches."""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            messagebox.showerror("Error", "Username or password cannot be empty!")
            return
        
        credentials = encrypt_credentials(username, password)
        gunbound_path = find_gunbound_executable(self.exe_entry.get().strip())
        if not gunbound_path:
            messagebox.showerror("Error", "No valid GunBound executable found! Please specify a valid path or ensure gunbound.exe/gme is in the directory.")
            return
        
        self.status_label.config(text="Status: Launching GunBound in suspended state...")
        self.root.update()
        self.process_info = run_gunbound(credentials, True, gunbound_path)
        
        if not self.process_info:
            messagebox.showerror("Error", f"Failed to start GunBound: {ctypes.GetLastError()}")
            self.status_label.config(text="Status: Failed to launch GunBound")
            return
        
        if self.apply_patches(self.process_info.hProcess, gunbound_path):
            messagebox.showinfo("Info", "GunBound started in suspended state with patches applied.")
        else:
            messagebox.showwarning("Warning", "GunBound started in suspended state, but some patches failed.")
    
    def resume_process(self):
        """Resume the suspended GunBound process."""
        if not self.process_info:
            messagebox.showerror("Error", "No process to resume!")
            return
        
        kernel32 = ctypes.WinDLL("kernel32")
        if kernel32.ResumeThread(self.process_info.hProcess) == -1:
            messagebox.showerror("Error", f"Failed to resume process: {ctypes.GetLastError()}")
            self.status_label.config(text="Status: Failed to resume process")
        else:
            messagebox.showinfo("Success", "Process resumed successfully.")
            self.status_label.config(text="Status: Process resumed")
            if self.exit_immediately:
                kernel32.CloseHandle(self.process_info.hThread)
                kernel32.CloseHandle(self.process_info.hProcess)
                self.root.quit()
    
    def terminate_process(self):
        """Terminate the GunBound process."""
        if not self.process_info:
            messagebox.showerror("Error", "No process to terminate!")
            return
        
        kernel32 = ctypes.WinDLL("kernel32")
        if kernel32.TerminateProcess(self.process_info.hProcess, 0):
            kernel32.CloseHandle(self.process_info.hThread)
            kernel32.CloseHandle(self.process_info.hProcess)
            self.process_info = None
            messagebox.showinfo("Success", "Process terminated successfully.")
            self.status_label.config(text="Status: Process terminated")
        else:
            messagebox.showerror("Error", f"Failed to terminate process: {ctypes.GetLastError()}")
            self.status_label.config(text="Status: Failed to terminate process")

def main():
    root = tk.Tk()
    app = GunBoundLauncherApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
