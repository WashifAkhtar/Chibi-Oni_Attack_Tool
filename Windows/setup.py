from cx_Freeze import setup, Executable
import sys

# Increase recursion limit
sys.setrecursionlimit(5000)

# Files to include in the build
includefiles = ['icon.ico']
# Modules to exclude from the build
excludes = []
# Additional packages to include
packages = []
# Base executable type (None by default)
base = None

# Set the base executable type for Windows
if sys.platform == "win32":
    base = "Win32GUI"

# Shortcut table for the MSI installer
shortcut_table = [
    ("DesktopShortcut",          # Shortcut
     "DesktopFolder",            # Directory
     "Chibi-Oni",                     # Name
     "TARGETDIR",                # Component
     "[TARGETDIR]\\chibi-oni.exe",    # Target
     None,                       # Arguments
     None,                       # Description
     None,                       # Hotkey
     None,                       # Icon
     None,                       # IconIndex
     None,                       # ShowCmd
     "TARGETDIR",                # WorkingDirectory
    )
]

# MSI data including shortcuts and license agreement
msi_data = {
    "Shortcut": shortcut_table
}

# MSI build options
bdist_msi_options = {'data': msi_data}

# Setup configuration
setup(
    version="1.0",
    description="Chibi-Oni",
    author="Washif Akhtar",
    name="Chibi-Oni",
    options={
        'build_exe': {'include_files': includefiles},
        'bdist_msi': bdist_msi_options,
    },
    executables=[
        Executable(
            script="chibi-oni.py",
            base=base,
            icon='icon.ico',
        )
    ]
)
