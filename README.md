# File-Lcoker-system
Encrypts and Decrypts files
Overview
Welcome to File-Locker-System, an educational cybersecurity project that demonstrates a secure and user-friendly tool for encrypting and decrypting files using the Fernet symmetric encryption algorithm from the cryptography library. Built with Python and a Tkinter-based graphical user interface (GUI), this application allows users to protect sensitive files with passwords, ensuring data confidentiality and privacy. The project serves as a practical example for learning about cryptography, data security, and GUI development.

#Project Purpose
This repository is created for educational purposes only, providing a hands-on example of cryptography concepts, file security, and user interface design. It is intended to enhance understanding of encryption techniques and promote awareness of secure data practices. Any misuse or malicious application of this code, such as unauthorized encryption or decryption of files, is strictly prohibited and not the responsibility of the author/uploader.

#How It Works
When you run the FileLocker.exe executable, a sleek GUI appears, featuring a dog icon, app details, and two prominent buttons: “Encrypt File” (red) and “Decrypt File” (green). Users can:

Select any file (e.g., images, documents, executables) to encrypt with a password, creating an .encrypted version and securely deleting the original.
Select an .encrypted file to decrypt with the same password, restoring the original file and removing the encrypted version.
The tool uses Fernet encryption for robust security, ensuring that only users with the correct password can access the files, all within a simple, intuitive interface.
#Features
File Encryption: Securely encrypts any file type using Fernet, requiring a password for protection.
File Decryption: Safely decrypts .encrypted files using the correct password, restoring the original file.
User-Friendly GUI: Offers an attractive Tkinter interface with clear feedback via success/error popups.
Password Authentication: Ensures only authorized users can encrypt/decrypt files, enhancing security.
#Build Instructions
To compile the project into an executable, use PyInstaller with the following command:

""pyinstaller --onefile --noconsole --icon=lock.ico file_locker.pyw""
--onefile: Creates a single .exe file for portability.
--noconsole: Ensures the executable runs without a console window (since file_locker.pyw uses Tkinter).
--icon=lock.ico: Embeds a custom icon (lock.ico) for the executable, enhancing its appearance as a security tool.
Ensure lock.ico (or a lock/dog-related icon) is in the same directory as file_locker.pyw, or provide the full path.
#Educational Use Only
This project is strictly for educational and research purposes to demonstrate cryptography, file security, and GUI development. It is not intended for any malicious or unauthorized use, such as encrypting others’ files without consent. The author/uploader bears no responsibility for any misuse, damage, or legal consequences resulting from the application of this code. Users are encouraged to adhere to ethical guidelines, legal standards, and institutional policies when exploring or extending this project.
