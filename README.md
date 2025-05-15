# Secure Folder Protection System

This system creates a password-protected folder in Windows that requires authentication before access.

## Features

- Password protection for accessing folders
- 3 attempt limit before security measures activate
- Automatic encryption and email of sensitive data after failed attempts
- Hidden folder with shortcut access mechanism
- Auto-locking on system startup

## Installation

1. Install required dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Run the set_password.py script to create your password:
   ```
   python set_password.py
   ```

3. Install the folder protection system:
   ```
   python folder_protector.py install
   ```

4. After installation, you'll see a shortcut named "SecretFolder.lnk" - use this to access your protected folder.

## Usage

- To open the protected folder: Double-click the "SecretFolder.lnk" shortcut and enter your password.
- To manually lock the folder: `python folder_protector.py lock`

## Security Notes

- The system will automatically delete specified folders after 3 failed password attempts
- Sensitive data will be encrypted and emailed to the configured address
- For optimal security, run the installation with administrator privileges

## Configuration

Edit the folder_protector.py file to change these settings:
- FOLDER_PATH: Name of the folder to protect
- MAX_ATTEMPTS: Number of password attempts allowed
- EMAIL_SENDER/EMAIL_RECIPIENT: Email addresses for security notifications
- FOLDERS_TO_DELETE/FOLDERS_TO_ENCRYPT: Folders to handle on security breach 