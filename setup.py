import sys

from cx_Freeze import setup, Executable

base=None

if sys.platform=='win32':
base="WIN32GUI"

setup(
    name = "tokengen",
    version = "2.1.0",
    description = "AWS Token Generator",
    options = {"build_exe": {
        'packages': ["os","sys","boto3","requests","getpass","configparser",
                    "base64","logging","xml","re","bs4","urllib"],
        'include_msvcr': True,
    }},
    executables = [Executable("STS-TokenGen.py",base=base)]
    )
