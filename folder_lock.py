import hashlib
import os
import shutil
import platform
import sys
import smtplib
import zipfile
from getpass import getpass
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import ssl

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

        # Send email with better error handling
        try:
            with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as smtp:
                print("[*] Attempting to connect to Gmail...")
                smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
                print("[*] Successfully logged in to Gmail")
                smtp.send_message(msg)
                print("[✓] Email sent successfully")
                return True
        except smtplib.SMTPAuthenticationError:
            print("[X] Authentication failed. Please check your email and app password.")
            print("[!] Make sure you have:")
            print("    1. Enabled 2-Step Verification")
            print("    2. Generated a new App Password")
            print("    3. Used the correct App Password")
            return False
        except Exception as e:
            print(f"[X] SMTP Error: {str(e)}")
            return False
            
    except Exception as e:
        print(f"[X] Error preparing email: {str(e)}")
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

def lock_folder():
    """Lock the folder by setting appropriate attributes."""
    if not os.path.exists(FOLDER_PATH):
        print(f"[!] Error: Folder '{FOLDER_PATH}' does not exist")
        sys.exit(1)
        
    try:
        if platform.system() == "Windows":
            os.system(f'attrib +h +s "{FOLDER_PATH}"')
        else:
            os.chmod(FOLDER_PATH, 0o000)
        print("[✓] Folder locked successfully.")
    except Exception as e:
        print(f"[X] Error locking folder: {e}")
        sys.exit(1)

def unlock_folder():
    """Unlock the folder by removing protection attributes."""
    try:
        if platform.system() == "Windows":
            os.system(f'attrib -h -s "{FOLDER_PATH}"')
        else:
            os.chmod(FOLDER_PATH, 0o755)
        print("[✓] Folder unlocked successfully.")
    except Exception as e:
        print(f"[X] Error unlocking folder: {e}")
        sys.exit(1)

def main():
    # Check if folder exists
    if not os.path.exists(FOLDER_PATH):
        print(f"[!] Error: Folder '{FOLDER_PATH}' does not exist")
        sys.exit(1)

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
            unlock_folder()
            return
        else:
            attempts += 1
            remaining = MAX_ATTEMPTS - attempts
            print(f"[X] Incorrect password ({attempts}/{MAX_ATTEMPTS})")
            if remaining > 0:
                print(f"[!] {remaining} attempts remaining")

    # If we reach here, it means MAX_ATTEMPTS wrong attempts
    self_destruct()

if __name__ == "__main__":
    main()
