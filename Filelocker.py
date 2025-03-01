import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import hashlib

# File Locker Class
class FileLocker:
    def __init__(self):
        self.key = None

    def generate_key(self):
        """Generate a key for encryption/decryption."""
        self.key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(self.key)

    def load_key(self):
        """Load the key from the current directory."""
        return open("secret.key", "rb").read()

    def hash_password(self, password):
        """Hash the password using SHA-256."""
        return hashlib.sha256(password.encode()).hexdigest()

    def encrypt_file(self, file_path, password):
        """Encrypt a file using a password."""
        if not self.key:
            self.generate_key()
        key = self.load_key()
        fernet = Fernet(key)

        # Hash the password and store it in the encrypted file
        hashed_password = self.hash_password(password)

        # Process the file in chunks
        chunk_size = 64 * 1024  # 64 KB
        try:
            with open(file_path, "rb") as file, open(file_path + ".encrypted", "wb") as encrypted_file:
                # Write the hashed password and a separator
                encrypted_file.write(hashed_password.encode() + b"|||")

                while True:
                    chunk = file.read(chunk_size)
                    if not chunk:
                        break
                    encrypted_chunk = fernet.encrypt(chunk)
                    encrypted_file.write(encrypted_chunk)

            os.remove(file_path)  # Delete the original file
            self.show_success("File encrypted successfully!")
        except Exception as e:
            self.show_error(f"Encryption failed: {e}")

    def decrypt_file(self, file_path, password):
        """Decrypt a file using a password."""
        key = self.load_key()
        fernet = Fernet(key)

        # Process the file in chunks
        chunk_size = 64 * 1024  # 64 KB
        try:
            with open(file_path, "rb") as encrypted_file, open(file_path[:-10], "wb") as decrypted_file:
                # Read the hashed password and separator
                metadata = b""
                while True:
                    chunk = encrypted_file.read(1)  # Read 1 byte at a time
                    if not chunk:
                        break
                    metadata += chunk
                    if metadata.endswith(b"|||"):
                        break

                # Split the metadata into hashed password and separator
                hashed_password, _, _ = metadata.partition(b"|||")

                # Validate the password
                if self.hash_password(password) != hashed_password.decode():
                    self.show_error("Incorrect password!")
                    return

                # Decrypt the data in chunks
                while True:
                    chunk = encrypted_file.read(chunk_size)
                    if not chunk:
                        break
                    decrypted_file.write(fernet.decrypt(chunk))

            os.remove(file_path)  # Delete the encrypted file
            self.show_success("File decrypted successfully!")
        except Exception as e:
            self.show_error(f"Decryption failed: {e}")

    def show_success(self, message):
        """Show a success message in a new window."""
        success_window = tk.Toplevel()
        success_window.title("Success")
        success_window.geometry("400x150")
        success_window.configure(bg="#4CAF50")  # Green background

        label = tk.Label(success_window, text=message, font=("Helvetica", 14, "bold"), bg="#4CAF50", fg="white")
        label.pack(pady=30)

        ok_button = tk.Button(success_window, text="OK", command=success_window.destroy, bg="#45a049", fg="white", font=("Helvetica", 12))
        ok_button.pack(pady=10)

    def show_error(self, message):
        """Show an error message in a new window."""
        error_window = tk.Toplevel()
        error_window.title("Error")
        error_window.geometry("400x150")
        error_window.configure(bg="#BF616A")  # Red background

        label = tk.Label(error_window, text=message, font=("Helvetica", 14, "bold"), bg="#BF616A", fg="white")
        label.pack(pady=30)

        ok_button = tk.Button(error_window, text="OK", command=error_window.destroy, bg="#A94442", fg="white", font=("Helvetica", 12))
        ok_button.pack(pady=10)


# GUI Class
class FileLockerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Locker System")
        self.root.geometry("600x500")
        self.root.configure(bg="#2E3440")  
        self.file_locker = FileLocker()

        # Load and display icon
        try:
            self.icon_image = tk.PhotoImage(file=r"c:\Users\Acer\Downloads\dog.png")  # Use raw string
            self.icon_label = tk.Label(root, image=self.icon_image, bg="#2E3440")
            self.icon_label.place(relx=0.5, rely=0.49, anchor="center")  # Adjusted position
        except Exception as e:
            print(f"Icon not found or failed to load: {e}")

        # App Details
        self.app_details = tk.Label(
            root,
            text="File Locker System\n\nSecurely encrypt and decrypt files of any type",
            font=("Chiller", 20),
            bg="#3B4252",  # Darker background for text
            fg="white",
            justify="left"
        )
        self.app_details.place(relx=0.5, rely=0.45, anchor="center")  # Adjusted position

        # Custom Buttons
        self.encrypt_button = tk.Button(
            root,
            text="Encrypt File",
            command=self.encrypt_file,
            bg="#FF5733",  # Red background
            fg="black",  # Black font
            font=("Helvetica", 12, "bold"),
            padx=20,
            pady=10
        )
        self.encrypt_button.place(relx=0.3, rely=0.75, anchor="center")  # Adjusted position

        self.decrypt_button = tk.Button(
            root,
            text="Decrypt File",
            command=self.decrypt_file,
            bg="#4CAF50",  # Green background
            fg="black",  # Black font
            font=("Helvetica", 12, "bold"),
            padx=20,
            pady=10
        )
        self.decrypt_button.place(relx=0.7, rely=0.75, anchor="center")  # Adjusted position

    def encrypt_file(self):
        """Handle file encryption."""
        file_path = filedialog.askopenfilename(title="Select a file to encrypt")
        if file_path:
            password = self.get_password()
            if password:
                self.file_locker.encrypt_file(file_path, password)

    def decrypt_file(self):
        """Handle file decryption."""
        file_path = filedialog.askopenfilename(title="Select a file to decrypt")
        if file_path:
            password = self.get_password()
            if password:
                self.file_locker.decrypt_file(file_path, password)

    def get_password(self):
        """Get password from user."""
        password = tk.simpledialog.askstring("Password", "Enter password:", show='*')
        if not password:
            self.show_error("Password cannot be empty!")
            return None
        return password

    def show_error(self, message):
        """Show an error message in a new window."""
        error_window = tk.Toplevel()
        error_window.title("Error")
        error_window.geometry("400x150")
        error_window.configure(bg="#BF616A")  

        label = tk.Label(error_window, text=message, font=("Helvetica", 14, "bold"), bg="#BF616A", fg="white")
        label.pack(pady=30)

        ok_button = tk.Button(error_window, text="OK", command=error_window.destroy, bg="#A94442", fg="white", font=("Helvetica", 12))
        ok_button.pack(pady=10)


# Main Function
if __name__ == "__main__":
    root = tk.Tk()
    app = FileLockerApp(root)
    root.mainloop()
