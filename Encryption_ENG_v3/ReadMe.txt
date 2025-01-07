Encryption / Decryption Tool v3

https://github.com/abdullah-erturk/Encryption-Decryption-Tool


### ATTENTION A file encrypted with v1 cannot be decrypted with v2 and v3. Take your precautions.


This program allows you to easily perform file encryption and decryption operations. 

You can securely encrypt your files and decrypt them whenever you need.

Virustotal Report:
https://www.virustotal.com/gui/file/2c4093461974b5e18462d103d4586e8d5aec14a5dd7d09edb5d0fc197aa51283


### FEATURES:

• AES-256 Encryption: Secure file encryption algorithm.

• Command-Line Usage: Fast and efficient operation.

• Right-Click Menu Integration: Easily encrypt or decrypt files via the right-click menu.

• User-Provided Password and Salt Value: Enhances security.

• Error Management: Handles scenarios such as missing files, incorrect passwords, or salts.


### USAGE:

The program offers 2 methods of use.

#### First Method (Installation):
Run the program and respond "yes" to the installation prompt that appears in the console screen.

The installation will be completed quickly.

Once installed, you can easily use it in the Windows environment by right-clicking any file to access the options "Encrypt File" for encryption or "Decrypt File" for encrypted files.

#### Second Method (Drag-and-Drop Encryption/Decryption):
Drag and drop any file with any extension onto the encrypt.exe file. A console screen will open, prompting you to enter a password and salt value.

To decrypt an encrypted file, drag and drop a .enc file onto the encrypt.exe file and enter the previously set password and salt value.


### HOW IT WORKS:

• The user is prompted to securely enter a password and salt value.

• An AES-256 key is generated using the password and salt information.

• The file is encrypted.

• The hash value of the original file is calculated and appended to the file.

• The file is encrypted using the AES algorithm.

• Information such as the Initialization Vector (IV) and the original file extension is prepended to the encrypted file.

• A New File is Created: The encrypted file is saved with a .enc extension, and the original file is deleted.

• The encrypted file does not store the password and salt values themselves but instead stores the hash of the user-entered password and salt.


### IMPORTANT NOTES:

If you forget the password, you will no longer be able to open your encrypted files. Therefore, it is important to securely store your password.

The program can encrypt any type of file without restrictions on file extension or size. Encrypting large files may take a considerable amount of time. For example, encrypting a 5GB file takes about 30 seconds. Of course, this time will vary depending on your computer's hardware.

The original file extension will be lost during encryption. For example, when you encrypt test.txt, the new file will be named test.enc with the .enc extension.

The program is completely open-source. You can download it from the repository, make any changes using Visual Studio, and compile it for your use.