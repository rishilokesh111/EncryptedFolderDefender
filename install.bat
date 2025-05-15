@echo off
echo Secure Folder Protection System - Installation
echo ============================================

REM Check for administrator privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running with administrator privileges...
) else (
    echo This installation requires administrator privileges.
    echo Please right-click on this file and select "Run as administrator"
    pause
    exit
)

REM Check if Python is installed
python --version >nul 2>&1
if %errorLevel% == 0 (
    echo Python found...
) else (
    echo Python not found! Please install Python 3.7 or later.
    echo Visit https://www.python.org/downloads/
    pause
    exit
)

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt

REM Create password if it doesn't exist
if not exist pass.txt (
    echo Setting up password...
    python set_password.py
) else (
    echo Password file found. To change password, run set_password.py separately.
)

REM Install folder protection
echo Installing folder protection...
python folder_protector.py install

echo.
echo Installation complete!
echo Use the SecretFolder.lnk shortcut to access your protected folder.
echo.
pause 