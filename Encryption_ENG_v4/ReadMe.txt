Encryption / Decryption Tool v4

https://github.com/abdullah-erturk/Encryption-Decryption-Tool


### ATTENTION A file encrypted with v1 cannot be decrypted with v2 - v3 - v4. Take your precautions.


This program allows you to easily perform file encryption and decryption operations. 

You can securely encrypt your files and decrypt them whenever you need.

Virustotal Report:
https://www.virustotal.com/gui/file/ee4e02361a710afc0defa9ac0dae3758ca3c461b293c43db1996609f413baba4


### FEATURES:

• AES-256 Encryption: Secure file encryption algorithm.

• Command Line Usage: Fast and effective operation.

• Right Click Menu Integration: Easily encrypt or decrypt files via the right click menu.

• Password and Salt Value Received from the User: Increases security.

• Error Management: Handling situations such as missing files, wrong passwords or salts.

• The program is portable, a file/folder encrypted on computer x can be decrypted again on computer y.

• The extension of the encrypted file is .enc.

• The extension of the encrypted folder is .encx.


### USAGE:

There are 2 types of usage methods for the program.

#### First method (installation):
Run the program, answer "yes" to the question about the installation of the program on the console screen.

The installation will be completed in a short time.

Now, when you right-click on any file and folder in the Windows environment, you can use the

"Encrypt File" for files and "Decrypt File" for encrypted files

and "Encrypt Folder" for folders and "Decrypt Folder" for encrypted folders options.

#### Second method (drag-drop-encrypt/decrypt):
Drag and drop any file or folder with any extension onto the encrypt.exe file, a console screen will pop up and ask you to specify the password and salt value.

To decrypt an encrypted file/folder, drag and drop the .enc or .encx file onto the encrypt.exe file and enter the password and salt value you specified before.


### HOW IT WORKS:

• The user is prompted to securely enter a password and salt value.

• An AES-256 key is generated using the password and salt information.

• The file is encrypted.

• The hash value of the original file is calculated and appended to the file.

• The file is encrypted using the AES algorithm.

• Information such as the Initialization Vector (IV) and the original file extension is prepended to the encrypted file.

• New File is Created: The encrypted file/folder is saved with the .enc or .encx extension and the original file is deleted.

• The encrypted file does not store the password and salt values themselves but instead stores the hash of the user-entered password and salt.


### IMPORTANT NOTES:

If you forget the password, you will not be able to open your encrypted files again. Therefore, it is important to keep your password safe.

The program can encrypt all types of files and folders without extension and size restrictions. The encryption process of large files/folders may take a long time.

The encryption time of a 5 GB file is approximately 30 seconds. Of course, this time will vary depending on the hardware power of your computer.

The original extension of encrypted files is lost during encryption. For example, when you encrypt the test.txt file, the new extension of the file will be test.enc with the .enc extension.

Regardless of the folder or file, encryption operations are restricted on the C:\ disk. Encryption can only be done on the desktop and Downloads folders on the C:\ disk.

Example:
A file or folder was encrypted on the D:\ disk and this encrypted file/folder was copied/moved to the main directory of the User folder.
Now that encrypted file/folder cannot be decrypted because it is in a restricted area.

When the user tries to decrypt the password, the program gives the following warning:

WARNING: This folder/file is a critical system folder/file used by the operating system, encryption is not allowed.

The purpose of this restriction is to prevent novice users from accidentally encrypting folders and files used by the operating system.

Encryption and decryption operations can be performed in the main directory of the C:\ disk, but encryption operations are prevented by the program in the folders used by the operating system and other folders and files within those folders.

These paths are:
@"C:\Windows"
@"C:\Windows\System32"
@"C:\Program Files"
@"C:\Program Files (x86)"
@"C:\Users"
@"C:\ProgramData"
@"C:\$RECYCLE.BIN"
@"C:\System Volume Information"
@"C:\Users\<Username>\AppData"
@"C:\Users\<Username>\Documents"

The folder paths that the program allows to encrypt on the C:\ disk are:
C:\Users\<Username>\Downloads
C:\Users\<Username>\Desktop

Encryption operations can be performed on other disks such as D:\ - E:\ - F:\ etc. in addition to these directories.

The program is completely open source. You can download it from the repo, make the changes you want with Visual Studio, compile it and use it.