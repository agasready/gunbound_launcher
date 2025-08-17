# GunBound Custom Launcher

A Python-based launcher for **GunBound**, offering account management, memory patching, file updates, and display mode configuration.  
This project is inspired by and builds upon [jglim/gunbound-launcher](https://github.com/jglim/gunbound-launcher).

## ✨ Features
- **Account Management**: Save, load, and delete encrypted credentials in `Launcher.ini`.
- **Memory Patching**: Apply custom patches to the GunBound process from `Launcher.ini`.
- **File Updates**: Download the latest `graphics.xfs` and `avatar.xfs` from the official server.
- **Display Modes**: Choose Full Screen (Voodoo2, DXwnd, Compat) or Windowed using the `compat` folder.
- **Process Control**: Launch in suspended mode, resume, or terminate the game process.

## ⚙️ Requirements
- Python 3.8 or higher  
- Python modules: `pycryptodome`, `requests`, `tkinter` (usually included with Python)  
- GunBound executable (`gunbound.exe` or `gunbound.gme`) in the same directory  
- `compat` folder with subfolders `1`, `2`, `3`, `4` (included in this repo)  
- Internet connection for file updates  

▶️ Usage
Account Setup
- Enter username and password
- Click Save Account to store encrypted credentials in Launcher.ini
- Select saved accounts from the dropdown to load credentials
- Click Delete Account to remove a selected account

Executable Path
- Click Browse to select gunbound.exe or gunbound.gme or whatever its name
- Or leave blank if it is in the same directory

Patch Settings
- Select a patch from the dropdown (loaded from Launcher.ini)
- Check Enable Patch to toggle patches on/off

Display Modes
- Click Display to select a display mode:
- Full Screen (Voodoo2, DXwnd, Compat)
- Windowed
- Files from the compat folder are copied based on the selected mode

Update Files
- Click Check Update to download the latest graphics.xfs and avatar.xfs

Launch Game
- Launch → Start GunBound with patches and auto-resume
- Start Suspend → Launch in suspended mode (manual resume needed)
- Resume → Continue a suspended process
- Terminate → Stop the game process

🧩 Patch Configuration
- Custom patches are defined in Launcher.ini under [PatchOptions] and [PatchStates].

Each patch includes:  
`Name<i>`: Patch name (e.g., no_sensor)  
`Address<i>`: Memory address in hex (e.g., 0x00572EB0)  
`Value<i>`: String to write (e.g., fAuswora.txd)  
`Size<i>`: Length in bytes (e.g., 13)  
`Patch<i>` (in [PatchStates]): True to enable, False to disable  

Example adding patch into Launcher.ini:
<pre>
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
</pre>

compat/: Contains subfolders
- 1: Voodoo2
- 2: DXwnd
- 3: Windowed
- 4: Compat

Launcher.ini: Auto-generated config file for accounts and patches
