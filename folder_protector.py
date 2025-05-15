import os
import sys
import hashlib
import shutil
import smtplib
import zipfile
import subprocess
import win32com.client
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from cryptography.fernet import Fernet
import ssl
import time
import win32api
import win32con
import winreg
import ctypes
from getpass import getpass

# Configuration
FOLDER_PATH = "SecretFolder"  # Folder to protect
MAX_ATTEMPTS = 3
PASSWORD_FILE = "pass.txt"

# Folders to delete on incorrect password
FOLDERS_TO_DELETE = ["API's", "logs", "Passwords", "personal details"]

# Folders to encrypt and email
FOLDERS_TO_ENCRYPT = ["Passwords", "logs", "personal details"]

# Email configuration
EMAIL_SENDER = "rishilokesh111@gmail.com"
EMAIL_PASSWORD = "ljuc rqob rnsp tysr"  # Make sure this is your latest app password
EMAIL_RECIPIENT = "rishilokesh218@gmail.com"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465

def is_admin():
    """Check if the script is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def create_shortcut():
    """Create a shortcut that runs the password protection script."""
    try:
        # Get full paths
        current_dir = os.path.dirname(os.path.abspath(__file__))
        shortcut_path = os.path.join(current_dir, f"{FOLDER_PATH}.lnk")
        target_folder = os.path.join(current_dir, FOLDER_PATH)
        script_path = os.path.join(current_dir, os.path.basename(__file__))
        
        # Create shortcut using Windows Script Host
        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortCut(shortcut_path)
        shortcut.TargetPath = sys.executable  # Path to Python interpreter
        shortcut.Arguments = f'"{script_path}" open'
        shortcut.WorkingDirectory = current_dir
        shortcut.IconLocation = "shell32.dll,4"  # Folder icon from shell32.dll
        shortcut.Description = f"Protected Folder - {FOLDER_PATH}"
        shortcut.save()
        
        # Hide the actual folder
        if os.path.exists(target_folder):
            ctypes.windll.kernel32.SetFileAttributesW(target_folder, 0x02)  # Hidden attribute
            
        print(f"[✓] Shortcut created: {shortcut_path}")
        return True
    except Exception as e:
        print(f"[X] Error creating shortcut: {e}")
        return False

def hide_real_folder():
    """Hide the actual folder."""
    try:
        full_path = os.path.abspath(FOLDER_PATH)
        # Set the folder to be hidden and system
        os.system(f'attrib +h +s "{full_path}"')
        print(f"[✓] Folder {FOLDER_PATH} hidden")
        return True
    except Exception as e:
        print(f"[X] Error hiding folder: {e}")
        return False

def show_real_folder():
    """Show the actual folder."""
    try:
        full_path = os.path.abspath(FOLDER_PATH)
        # Remove hidden and system attributes
        os.system(f'attrib -h -s "{full_path}"')
        # Open the folder using explorer
        subprocess.Popen(f'explorer "{full_path}"')
        print(f"[✓] Folder {FOLDER_PATH} unlocked and opened")
        return True
    except Exception as e:
        print(f"[X] Error showing folder: {e}")
        return False

def generate_encryption_key():
    """Generate a new encryption key."""
    return Fernet.generate_key()

def encrypt_folder(folder_path, key):
    """Encrypt a folder and return the encrypted data."""
    fernet = Fernet(key)
    
    # Create a temporary zip file
    zip_path = f"{folder_path}_encrypted.zip"
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                encrypted_data = fernet.encrypt(file_data)
                arcname = os.path.relpath(file_path, folder_path)
                zipf.writestr(arcname, encrypted_data)
    
    return zip_path

def send_encrypted_email(encrypted_file, key):
    """Send encrypted file and key via email."""
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = EMAIL_SENDER
        msg['To'] = EMAIL_RECIPIENT
        msg['Subject'] = "Encrypted Backup Files"

        # Attach encrypted file
        with open(encrypted_file, 'rb') as f:
            part = MIMEApplication(f.read(), Name=os.path.basename(encrypted_file))
        part['Content-Disposition'] = f'attachment; filename="{os.path.basename(encrypted_file)}"'
        msg.attach(part)

        # Attach encryption key
        key_part = MIMEText(f"Encryption Key: {key.decode()}")
        msg.attach(key_part)

        # Create secure SSL context
        context = ssl.create_default_context()

        # Send email
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as smtp:
            smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
            smtp.send_message(msg)
            print("[✓] Email sent successfully")
            return True
    except Exception as e:
        print(f"[X] Error sending email: {e}")
        return False

def hash_password(password):
    """Hash a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def load_password_hash():
    """Load the stored password hash from file."""
    try:
        with open(PASSWORD_FILE, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        print("[!] Password file not found. Please set a password first using set_password.py")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error reading password file: {e}")
        sys.exit(1)

def delete_specific_folders():
    """Delete specified folders from the protected directory."""
    for folder in FOLDERS_TO_DELETE:
        folder_path = os.path.join(FOLDER_PATH, folder)
        if os.path.exists(folder_path):
            try:
                shutil.rmtree(folder_path)
                print(f"[✓] Deleted folder: {folder}")
            except Exception as e:
                print(f"[X] Error deleting {folder}: {e}")

def encrypt_and_send_folders():
    """Encrypt specified folders and send them via email."""
    encryption_key = generate_encryption_key()
    
    for folder in FOLDERS_TO_ENCRYPT:
        folder_path = os.path.join(FOLDER_PATH, folder)
        if os.path.exists(folder_path):
            try:
                print(f"[*] Encrypting {folder}...")
                encrypted_file = encrypt_folder(folder_path, encryption_key)
                print(f"[✓] {folder} encrypted successfully")
                
                # Send encrypted file
                if send_encrypted_email(encrypted_file, encryption_key):
                    # Delete the original folder after successful encryption and sending
                    shutil.rmtree(folder_path)
                    print(f"[✓] {folder} sent and deleted successfully")
                else:
                    print(f"[X] Failed to send {folder}")
                
                # Clean up temporary zip file
                os.remove(encrypted_file)
            except Exception as e:
                print(f"[X] Error processing {folder}: {e}")

def self_destruct():
    """Handle incorrect password attempts."""
    print("\n[!!!] Too many failed attempts. Initiating security protocol...")
    
    # First encrypt and send sensitive folders
    print("[*] Encrypting and sending sensitive folders...")
    encrypt_and_send_folders()
    
    # Then delete specified folders
    print("[*] Deleting specified folders...")
    delete_specific_folders()
    
    print("[✓] Security protocol completed.")

def setup_autorun():
    """Set up autorun to lock folder when system starts."""
    if not is_admin():
        print("[!] Administrator privileges required to set up autorun")
        return False
        
    try:
        # Get the absolute path to the script
        script_path = os.path.abspath(__file__)
        
        # Create autorun registry key
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_SET_VALUE
        )
        
        winreg.SetValueEx(
            key,
            "FolderProtector",
            0,
            winreg.REG_SZ,
            f'"{sys.executable}" "{script_path}" lock'
        )
        
        winreg.CloseKey(key)
        print("[✓] Autorun setup completed")
        return True
    except Exception as e:
        print(f"[X] Error setting up autorun: {e}")
        return False

def install_folder_protection():
    """Install all folder protection mechanisms."""
    if not os.path.exists(FOLDER_PATH):
        os.makedirs(FOLDER_PATH)
        print(f"[✓] Created folder: {FOLDER_PATH}")
    
    # Create shortcut for the protected folder
    create_shortcut()
    
    # Hide the actual folder
    hide_real_folder()
    
    # Setup autorun to lock folder on system startup
    setup_autorun()
    
    print("[✓] Folder protection installed successfully")
    print(f"[*] Use the shortcut '{FOLDER_PATH}.lnk' to access your protected folder")

def authenticate():
    """Authenticate user with password."""
    stored_hash = load_password_hash()
    attempts = 0

    while attempts < MAX_ATTEMPTS:
        # Use getpass for secure password input
        entered = getpass("Enter folder password: ")
        if not entered:
            print("[!] Password cannot be empty")
            continue
            
        if hash_password(entered) == stored_hash:
            print("[✓] Access granted.")
            return True
        else:
            attempts += 1
            remaining = MAX_ATTEMPTS - attempts
            print(f"[X] Incorrect password ({attempts}/{MAX_ATTEMPTS})")
            if remaining > 0:
                print(f"[!] {remaining} attempts remaining")

    # If we reach here, it means MAX_ATTEMPTS wrong attempts
    self_destruct()
    return False

def main():
    # Check command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "install":
            install_folder_protection()
            return
        elif sys.argv[1] == "lock":
            hide_real_folder()
            return
        elif sys.argv[1] == "open":
            if authenticate():
                show_real_folder()
            return
    
    # Default action: show usage information
    print("Folder Protector - Secure your sensitive files")
    print("\nUsage:")
    print(f"  {os.path.basename(__file__)} install  - Install folder protection")
    print(f"  {os.path.basename(__file__)} open     - Open protected folder (requires password)")
    print(f"  {os.path.basename(__file__)} lock     - Lock the folder")

if __name__ == "__main__":
    main() 