GunBound Launcher
A Python-based launcher for GunBound, offering account management, memory patching, file updates, and display mode configuration. This project is inspired by and builds upon jglim/gunbound-launcher.

Features

Account Management: Save, load, and delete encrypted credentials in Launcher.ini.
Memory Patching: Apply custom patches to the GunBound process from Launcher.ini.
File Updates: Download the latest graphics.xfs and avatar.xfs from the official server.
Display Modes: Choose Full Screen (Voodoo2, DXwnd, Compat) or Windowed using the compat folder.
Process Control: Launch in suspended mode, resume, or terminate the game process.

Requirements

Python 3.8 or higher.
Python modules: pycryptodome, requests, tkinter (usually included with Python).
GunBound executable (gunbound.exe or gunbound.gme) in the same directory.
compat folder with subfolders 1, 2, 3, 4 (included in this repo).
Internet connection for file updates.

Installation

Clone the repository:git clone https://github.com/agasready/gunbound_launcher.git
cd gunbound_launcher


Install Python dependencies:pip install pycryptodome requests


Place gunbound.exe or gunbound.gme in the gunbound_launcher directory.
The compat folder (with subfolders 1, 2, 3, 4) is included for display modes.

Usage

Run the launcher:
python GB_launcher_v2.5.py


Account Setup:

Enter username and password.
Click "Save Account" to store encrypted credentials in Launcher.ini.
Select saved accounts from the dropdown to load credentials.
Click "Delete Account" to remove a selected account.


Executable Path:

Click "Browse" to select gunbound.exe or gunbound.gme, or leave blank if in the same directory.


Patch Settings:

Select a patch from the dropdown (loaded from Launcher.ini).
Check "Enable Patch" to toggle patches on/off.


Display Modes:

Click "Display" to select Full Screen (Voodoo2, DXwnd, Compat) or Windowed.
Files from the compat folder are copied based on the selected mode.


Update Files:

Click "Check Update" to download the latest graphics.xfs and avatar.xfs.


Launch Game:

Click "Launch" to start GunBound with patches and auto-resume.
Click "Start Suspend" to launch in suspended mode (requires manual resume).
Click "Resume" to continue a suspended process.
Click "Terminate" to stop the game process.



Patch Configuration
Custom patches are defined in Launcher.ini under [PatchOptions] and [PatchStates]. Each patch has:

Name<i>: Patch name (e.g., no_sensor).
Address<i>: Memory address in hexadecimal (e.g., 0x00572EB0).
Value<i>: String to write to memory (e.g., fAuswora.txd).
Size<i>: String length in bytes (e.g., 13).
Patch<i> (in [PatchStates]): True to enable, False to disable.

Example Launcher.ini patch configuration:
[PatchOptions]
Name1=no_sensor
Address1=0x00572EB0
Value1=fAuswora.txd
Size1=13
Name2=Avatar_Permanen
Address2=0x0057347C
Value2=galon.xfs
Size2=19

[PatchStates]
Patch1=True
Patch2=True

Folder Structure

GB_launcher_v2.5.py: Main launcher script.
compat/: Contains subfolders 1 (Voodoo2), 2 (DXwnd), 3 (Windowed), 4 (Compat) for display mode files.
Launcher.ini: Auto-generated config file for accounts and patches.
