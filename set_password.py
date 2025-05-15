import hashlib
import os
import sys
from getpass import getpass

def hash_password(password):
    """Hash a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def save_password_hash(hashed_password, file_path="pass.txt"):
    """Save the hashed password to a file."""
    try:
        with open(file_path, "w") as f:
            f.write(hashed_password)
        return True
    except IOError as e:
        print(f"Error saving password: {e}")
        return False

def main():
    # Get password securely without displaying it
    password = getpass("Enter your password: ")
    
    # Validate password
    if not password:
        print("Error: Password cannot be empty")
        sys.exit(1)
    
    # Hash the password
    hashed = hash_password(password)
    
    # Save the hash
    if save_password_hash(hashed):
        print("Password saved successfully.")
    else:
        print("Failed to save password.")
        sys.exit(1)

if __name__ == "__main__":
    main()
