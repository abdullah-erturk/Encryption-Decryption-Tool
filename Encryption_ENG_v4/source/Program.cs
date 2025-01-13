﻿using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace Encryption
{
    class CryptWork
    {
        static void DisplayCountdown(int seconds)
        {
            for (int i = seconds; i > 0; i--)
            {
                Console.Write($"The program will close automatically in {i} seconds.");
                Thread.Sleep(1000); // Waits for 1 second
                Console.SetCursorPosition(0, Console.CursorTop); // Moves the cursor to the beginning of the line
            }
            Environment.Exit(0); // Closes the program
        }

        static async Task Main(string[] args)
        {
            int width = 92;
            int height = 21;

            Console.SetWindowSize(width, height);
            Console.SetBufferSize(width, height);

            Console.Title = "Encryption / Decryption Tool v4 | made by Abdullah ERTÜRK";

            if (args.Length < 1)
            {
                ShowUsage();
                Console.ReadLine();
                return;
            }

            var mode = args[0];

            if (mode == "-i")
            {
                InstallProgram();
                return;
            }
            else if (mode == "-u")
            {
                UninstallProgram();
                return;
            }

            if (args.Length == 1)
            {
                var inputFilePath = args[0];
                await HandleDragAndDrop(inputFilePath);
                return;
            }

            if (args.Length < 2)
            {
                ShowUsage();
                Console.ReadLine();
                return;
            }

            var inputFilePathWithMode = args[1];

            if (!File.Exists(inputFilePathWithMode) && !Directory.Exists(inputFilePathWithMode))
            {
                Console.WriteLine("");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Error: File or folder not found. \n{inputFilePathWithMode}");
                Console.ResetColor();

                Console.ReadLine();
                return;
            }

            // Check critical system folders
            if (IsCriticalSystemFolder(inputFilePathWithMode))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("");
                Console.WriteLine("WARNING: This folder/file is a critical system folder/file used by the operating system, encryption is not allowed.");
                Console.ResetColor();
                Console.WriteLine("");
                DisplayCountdown(5);
            }

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("");
            Console.WriteLine($"Processing file or folder: \n{inputFilePathWithMode}");
            Console.WriteLine("");
            Console.ResetColor();

            if (inputFilePathWithMode.EndsWith(".encx"))
            {
                if (mode == "-d")
                {
                    Console.Write("Please enter the password: ");
                    var passwordInput = await ReadPasswordAsync();
                    var password = Encoding.UTF8.GetBytes(passwordInput);

                    Console.WriteLine("");
                    Console.Write("Please enter the salt value: ");
                    var saltInput = await ReadPasswordAsync();
                    var salt = Encoding.UTF8.GetBytes(saltInput);

                    byte[] key = GenerateKey(password, salt);
                    byte[] aesKey = new byte[32]; // 32-byte key for AES-256
                    Array.Copy(key, aesKey, 32);

                    try
                    {
                        Console.WriteLine("");
                        Console.WriteLine("Decrypting, please wait...");
                        Console.WriteLine("");
                        DecryptFolder(inputFilePathWithMode, aesKey, password, salt);
                    }
                    catch (FileNotFoundException ex)
                    {
                        Console.WriteLine("");
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"Error: File not found. {ex.Message}");
                        Console.ResetColor();
                        Console.WriteLine("");
                        DisplayCountdown(5);
                    }
                    catch (CryptographicException)
                    {
                        Console.WriteLine("");
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Error: Incorrect password or salt value entered.");
                        Console.WriteLine("");
                        Console.ResetColor();
                        DisplayCountdown(5);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("");
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"Unexpected error occurred: {ex.Message}");
                        Console.ResetColor();
                        Console.WriteLine("");
                        DisplayCountdown(5);
                    }
                    return;
                }
                else
                {
                    Console.WriteLine("");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("WARNING: This file is an encrypted folder, it cannot be encrypted again.");
                    Console.ResetColor();
                    Console.WriteLine("");
                    DisplayCountdown(5);
                }
            }

            if (mode == "-e" && inputFilePathWithMode.EndsWith(".enc"))
            {
                Console.WriteLine("");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("WARNING: The file is already encrypted, it cannot be encrypted again.");
                Console.WriteLine("");
                Console.ResetColor();
                DisplayCountdown(5);
            }

            Console.WriteLine("");
            Console.Write("Please enter the password: ");
            var passwordInput2 = await ReadPasswordAsync();
            var password2 = Encoding.UTF8.GetBytes(passwordInput2);

            Console.WriteLine("");
            Console.Write("Please enter the salt value: ");
            var saltInput2 = await ReadPasswordAsync();
            var salt2 = Encoding.UTF8.GetBytes(saltInput2);

            byte[] key2 = GenerateKey(password2, salt2);
            byte[] aesKey2 = new byte[32]; // 32-byte key for AES-256
            Array.Copy(key2, aesKey2, 32);

            try
            {
                if (mode == "-e")
                {
                    Console.WriteLine("");
                    Console.WriteLine("Encrypting, please wait...");
                    Console.WriteLine("");
                    if (File.Exists(inputFilePathWithMode))
                    {
                        EncryptFile(inputFilePathWithMode, aesKey2, password2, salt2);
                    }
                    else if (Directory.Exists(inputFilePathWithMode))
                    {
                        EncryptFolder(inputFilePathWithMode, aesKey2, password2, salt2);
                    }
                }
                else if (mode == "-d")
                {
                    Console.WriteLine("");
                    Console.WriteLine("Decrypting, please wait...");
                    Console.WriteLine("");
                    if (File.Exists(inputFilePathWithMode))
                    {
                        DecryptFile(inputFilePathWithMode, aesKey2, password2, salt2);
                    }
                    else if (Directory.Exists(inputFilePathWithMode))
                    {
                        DecryptFolder(inputFilePathWithMode, aesKey2, password2, salt2);
                    }
                }
                else
                {
                    Console.WriteLine("");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("You must select the encryption/decryption mode with -e or -d.");
                    Console.ResetColor();
                    Console.ReadLine();
                }
            }
            catch (FileNotFoundException ex)
            {
                Console.WriteLine("");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Error: File not found. {ex.Message}");
                Console.ResetColor();
                Console.WriteLine("");
                DisplayCountdown(5);
            }
            catch (CryptographicException)
            {
                Console.WriteLine("");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Error: Incorrect password or salt value entered.");
                Console.ResetColor();
                Console.WriteLine("");
                DisplayCountdown(5);
            }
            catch (Exception ex)
            {
                Console.WriteLine("");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Unexpected error occurred: {ex.Message}");
                Console.ResetColor();
                Console.WriteLine("");
                DisplayCountdown(5);
            }
        }

        static async Task HandleDragAndDrop(string inputFilePath)
        {
            if (!File.Exists(inputFilePath) && !Directory.Exists(inputFilePath))
            {
                Console.WriteLine("");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Error: File or folder not found. \n{inputFilePath}");
                Console.ResetColor();
                Console.ReadLine();
                return;
            }

            // Check critical system folders
            if (IsCriticalSystemFolder(inputFilePath))
            {
                Console.WriteLine("");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("WARNING: This folder/file is a critical system folder/file used by the operating system, encryption is not allowed.");
                Console.ResetColor();
                Console.WriteLine("");
                DisplayCountdown(5);
            }

            Console.WriteLine("");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"Processing file or folder: \n{inputFilePath}");
            Console.ResetColor();
            Console.WriteLine("");

            if (inputFilePath.EndsWith(".enc"))
            {
                Console.Write("Please enter the password: ");
                var passwordInput = await ReadPasswordAsync();
                var password = Encoding.UTF8.GetBytes(passwordInput);

                Console.WriteLine("");
                Console.Write("Please enter the salt value: ");
                var saltInput = await ReadPasswordAsync();
                var salt = Encoding.UTF8.GetBytes(saltInput);

                byte[] key = GenerateKey(password, salt);
                byte[] aesKey = new byte[32]; // 32-byte key for AES-256
                Array.Copy(key, aesKey, 32);

                try
                {
                    Console.WriteLine("");
                    Console.WriteLine("Decrypting, please wait...");
                    Console.WriteLine("");
                    DecryptFile(inputFilePath, aesKey, password, salt);
                }
                catch (FileNotFoundException ex)
                {
                    Console.WriteLine("");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Error: File not found. {ex.Message}");
                    Console.ResetColor();
                    Console.WriteLine("");
                    DisplayCountdown(5);
                }
                catch (CryptographicException)
                {
                    Console.WriteLine("");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Error: Incorrect password or salt value entered.");
                    Console.ResetColor();
                    Console.WriteLine("");
                    DisplayCountdown(5);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Unexpected error occurred: {ex.Message}");
                    Console.ResetColor();
                    Console.WriteLine("");
                    DisplayCountdown(5);
                }
            }
            else if (inputFilePath.EndsWith(".encx"))
            {
                Console.Write("Please enter the password: ");
                var passwordInput = await ReadPasswordAsync();
                var password = Encoding.UTF8.GetBytes(passwordInput);

                Console.WriteLine("");
                Console.Write("Please enter the salt value: ");
                var saltInput = await ReadPasswordAsync();
                var salt = Encoding.UTF8.GetBytes(saltInput);

                byte[] key = GenerateKey(password, salt);
                byte[] aesKey = new byte[32]; // 32-byte key for AES-256
                Array.Copy(key, aesKey, 32);

                try
                {
                    Console.WriteLine("");
                    Console.WriteLine("Decrypting, please wait...");
                    Console.WriteLine("");
                    DecryptFolder(inputFilePath, aesKey, password, salt);
                }
                catch (FileNotFoundException ex)
                {
                    Console.WriteLine("");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Error: File not found. {ex.Message}");
                    Console.ResetColor();
                    Console.WriteLine("");
                    DisplayCountdown(5);
                }
                catch (CryptographicException)
                {
                    Console.WriteLine("");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Error: Incorrect password or salt value entered.");
                    Console.ResetColor();
                    Console.WriteLine("");
                    DisplayCountdown(5);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Unexpected error occurred: {ex.Message}");
                    Console.ResetColor();
                    Console.WriteLine("");
                    DisplayCountdown(5);
                }
            }
            else
            {
                Console.Write("Please enter the password: ");
                var passwordInput = await ReadPasswordAsync();
                var password = Encoding.UTF8.GetBytes(passwordInput);

                Console.WriteLine("");
                Console.Write("Please enter the salt value: ");
                var saltInput = await ReadPasswordAsync();
                var salt = Encoding.UTF8.GetBytes(saltInput);

                byte[] key = GenerateKey(password, salt);
                byte[] aesKey = new byte[32]; // 32-byte key for AES-256
                Array.Copy(key, aesKey, 32);

                try
                {
                    Console.WriteLine("");
                    Console.WriteLine("Encrypting, please wait...");
                    Console.WriteLine("");
                    if (File.Exists(inputFilePath))
                    {
                        EncryptFile(inputFilePath, aesKey, password, salt);
                    }
                    else if (Directory.Exists(inputFilePath))
                    {
                        EncryptFolder(inputFilePath, aesKey, password, salt);
                    }
                }
                catch (FileNotFoundException ex)
                {
                    Console.WriteLine("");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Error: File not found. {ex.Message}");
                    Console.ResetColor();
                    Console.WriteLine("");
                    DisplayCountdown(5);
                }
                catch (CryptographicException)
                {
                    Console.WriteLine("");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Error: Incorrect password or salt value entered.");
                    Console.ResetColor();
                    Console.WriteLine("");
                    DisplayCountdown(5);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Unexpected error occurred: {ex.Message}");
                    Console.ResetColor();
                    Console.WriteLine("");
                    DisplayCountdown(5);
                }
            }
        }

        // Function to check critical system folders
        static bool IsCriticalSystemFolder(string path)
        {
            string[] criticalFolders = new string[]
            {
                @"C:\Windows",
                @"C:\Windows\System32",
                @"C:\Program Files",
                @"C:\Program Files (x86)",
                @"C:\Users",
                @"C:\ProgramData",
                @"C:\$RECYCLE.BIN",
                @"C:\System Volume Information",
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), // C:\Users\<Username>\AppData
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) // C:\Users\<Username>\Documents
            };

            // Add Downloads and Desktop directories
            string downloadsFolder = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + @"\Downloads";
            string desktopFolder = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);

            foreach (var folder in criticalFolders)
            {
                if (path.StartsWith(folder, StringComparison.OrdinalIgnoreCase) &&
                    !path.StartsWith(downloadsFolder, StringComparison.OrdinalIgnoreCase) &&
                    !path.StartsWith(desktopFolder, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        [DllImport("shell32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern void SHChangeNotify(uint wEventId, uint uFlags, IntPtr dwItem1, IntPtr dwItem2);

        static void InstallProgram()
        {
            try
            {
                string sourceFilePath = Process.GetCurrentProcess().MainModule.FileName;
                string destinationFilePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "encrypt.exe");

                File.Copy(sourceFilePath, destinationFilePath, true);

                using (RegistryKey key = Registry.ClassesRoot.CreateSubKey(@"*\shell\Encrypt File"))
                {
                    key.SetValue("MUIVerb", "Encrypt File");
                    key.SetValue("Icon", @"C:\Windows\system32\imageres.dll,54");
                }

                using (RegistryKey key = Registry.ClassesRoot.CreateSubKey(@"*\shell\Encrypt File\command"))
                {
                    key.SetValue("", $"\"{destinationFilePath}\" -e \"%1\"");
                }

                using (RegistryKey key = Registry.ClassesRoot.CreateSubKey(@"Directory\shell\Encrypt Folder"))
                {
                    key.SetValue("MUIVerb", "Encrypt Folder");
                    key.SetValue("Icon", @"C:\Windows\system32\imageres.dll,54");
                }

                using (RegistryKey key = Registry.ClassesRoot.CreateSubKey(@"Directory\shell\Encrypt Folder\command"))
                {
                    key.SetValue("", $"\"{destinationFilePath}\" -e \"%1\"");
                }

                using (RegistryKey key = Registry.ClassesRoot.CreateSubKey(@".enc"))
                {
                    key.SetValue("", ".enc File");
                }

                using (RegistryKey key = Registry.ClassesRoot.CreateSubKey(@".enc\shell\Decrypt File"))
                {
                    key.SetValue("MUIVerb", "Decrypt File");
                    key.SetValue("Icon", @"C:\Windows\system32\imageres.dll,77");
                }

                using (RegistryKey key = Registry.ClassesRoot.CreateSubKey(@".enc\DefaultIcon"))
                {
                    key.SetValue("", @"C:\Windows\system32\imageres.dll,54");
                }

                using (RegistryKey key = Registry.ClassesRoot.CreateSubKey(@".enc\shell\Decrypt File\command"))
                {
                    key.SetValue("", $"\"{destinationFilePath}\" -d \"%1\"");
                }

                using (RegistryKey key = Registry.ClassesRoot.CreateSubKey(@".encx"))
                {
                    key.SetValue("", ".encx File");
                }

                using (RegistryKey key = Registry.ClassesRoot.CreateSubKey(@".encx\shell\Decrypt Folder"))
                {
                    key.SetValue("MUIVerb", "Decrypt Folder");
                    key.SetValue("Icon", @"C:\Windows\system32\imageres.dll,77");
                }

                using (RegistryKey key = Registry.ClassesRoot.CreateSubKey(@".encx\DefaultIcon"))
                {
                    key.SetValue("", @"C:\Windows\system32\imageres.dll,54");
                }

                using (RegistryKey key = Registry.ClassesRoot.CreateSubKey(@".encx\shell\Decrypt Folder\command"))
                {
                    key.SetValue("", $"\"{destinationFilePath}\" -d \"%1\"");
                }

                Console.WriteLine("");
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Program installed successfully and registry entries created.");
                Console.ResetColor();
                Console.WriteLine("");
                Console.WriteLine("Press ENTER to exit.");

                // Refresh icon cache
                SHChangeNotify(0x08000000, 0x0000, IntPtr.Zero, IntPtr.Zero);
            }
            catch (Exception ex)
            {
                Console.WriteLine("");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"An error occurred during installation: {ex.Message}");
                Console.ResetColor();
            }
        }

        static void UninstallProgram()
        {
            try
            {
                string destinationFilePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "encrypt.exe");

                if (File.Exists(destinationFilePath))
                {
                    File.Delete(destinationFilePath);
                }

                using (RegistryKey key = Registry.ClassesRoot.OpenSubKey(@"*\shell", true))
                {
                    if (key != null)
                    {
                        key.DeleteSubKeyTree("Encrypt File", false);
                    }
                }

                using (RegistryKey key = Registry.ClassesRoot.OpenSubKey(@"Directory\shell", true))
                {
                    if (key != null)
                    {
                        key.DeleteSubKeyTree("Encrypt Folder", false);
                    }
                }

                using (RegistryKey key = Registry.ClassesRoot.OpenSubKey(@".enc\shell", true))
                {
                    if (key != null)
                    {
                        key.DeleteSubKeyTree("Decrypt File", false);
                    }
                }

                using (RegistryKey key = Registry.ClassesRoot.OpenSubKey(@".encx\shell", true))
                {
                    if (key != null)
                    {
                        key.DeleteSubKeyTree("Decrypt Folder", false);
                    }
                }

                using (RegistryKey key = Registry.ClassesRoot.OpenSubKey(@".enc", true))
                {
                    if (key != null)
                    {
                        key.DeleteSubKeyTree("", false);
                    }
                }

                using (RegistryKey key = Registry.ClassesRoot.OpenSubKey(@".encx", true))
                {
                    if (key != null)
                    {
                        key.DeleteSubKeyTree("", false);
                    }
                }

                Console.WriteLine("");
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Program uninstalled successfully and registry entries deleted.");
                Console.ResetColor();

                // Refresh icon cache
                SHChangeNotify(0x08000000, 0x0000, IntPtr.Zero, IntPtr.Zero);
            }
            catch (Exception ex)
            {
                Console.WriteLine("");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"An error occurred during uninstallation: {ex.Message}");
                Console.ResetColor();
            }
        }

        static byte[] GenerateKey(byte[] password, byte[] salt)
        {
            using (var rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA512))
            {
                return rfc2898DeriveBytes.GetBytes(64);
            }
        }

        static void ShowUsage()
        {
            Console.WriteLine("");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Encryption / Decryption Tool v4 ");
            Console.ResetColor();
            Console.WriteLine("");
            Console.WriteLine("https://github.com/abdullah-erturk");
            Console.WriteLine("");
            Console.WriteLine("");
            Console.ForegroundColor = ConsoleColor.DarkCyan;
            Console.WriteLine("Encrypt or decrypt any file or folder in Windows environment with a password you set.");
            Console.ResetColor();
            Console.WriteLine("");
            Console.WriteLine("");

            string encryptExePath = @"C:\Windows\encrypt.exe";

            if (File.Exists(encryptExePath))
            {
                while (true)
                {
                    Console.ForegroundColor = ConsoleColor.DarkYellow;
                    Console.WriteLine("The program is already installed. Do you want to uninstall it? (y/n)");
                    Console.ResetColor();
                    Console.WriteLine("");
                    Console.Write("Your choice: ");
                    string answer = Console.ReadLine();

                    if (answer.ToLower() == "y")
                    {
                        UninstallProgram();
                        Console.WriteLine("");
                        Console.WriteLine("Press ENTER to exit.");
                        break;
                    }
                    else if (answer.ToLower() == "n")
                    {
                        Console.WriteLine("");
                        Console.WriteLine("Program uninstallation cancelled.");
                        Console.WriteLine("");
                        Console.WriteLine("Press ENTER to exit.");
                        break;
                    }
                    else
                    {
                        Console.WriteLine("");
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Invalid option! Please enter 'y' or 'n'.");
                        Console.ResetColor();
                        Console.WriteLine("");
                        Console.WriteLine("Press ENTER to try again.");
                        Console.ReadLine();
                        Console.Clear();
                    }
                }
            }
            else
            {
                while (true)
                {
                    Console.ForegroundColor = ConsoleColor.DarkYellow;
                    Console.WriteLine("Do you want to install the program? (y/n)");
                    Console.ResetColor();
                    Console.WriteLine("");
                    Console.WriteLine("y = Installs the program to the Windows directory and creates right-click registry entries.");
                    Console.WriteLine("n = Removes the program from the Windows directory and deletes right-click registry entries.");
                    Console.WriteLine("");
                    Console.Write("Your choice: ");
                    string answer = Console.ReadLine();

                    if (answer.ToLower() == "y")
                    {
                        InstallProgram();
                        AddRegistryEntry();
                        break;
                    }
                    else if (answer.ToLower() == "n")
                    {
                        Console.WriteLine("");
                        Console.WriteLine("Program installation cancelled.");
                        Console.WriteLine("");
                        Console.WriteLine("Press ENTER to exit.");
                        break;
                    }
                    else
                    {
                        Console.WriteLine("");
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Invalid option! Please enter 'y' or 'n'.");
                        Console.ResetColor();
                        Console.WriteLine("");
                        Console.WriteLine("Press ENTER to try again.");
                        Console.ReadLine();
                        Console.Clear();
                    }
                }
            }
        }

        static void DisplayProgressBar(double progress)
        {
            int totalBlocks = 50; // Total length of the progress bar
            int filledBlocks = (int)(progress * totalBlocks);

            Console.SetCursorPosition(0, Console.CursorTop);
            Console.Write("[");
            Console.Write(new string('=', filledBlocks));
            Console.Write(new string(' ', totalBlocks - filledBlocks));
            Console.Write($"] {progress:P0}");
        }

        static void EncryptFile(string inputFilePath, byte[] aesKey, byte[] password, byte[] salt)
        {
            if (inputFilePath.EndsWith(".enc"))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("WARNING: The file is already encrypted, it cannot be encrypted again.");
                Console.ResetColor();
                Console.WriteLine("");
                DisplayCountdown(5);
            }

            var tempOutputFilePath = inputFilePath + ".temp";
            try
            {
                using (var inputStream = File.OpenRead(inputFilePath))
                using (var outputStream = File.Create(tempOutputFilePath))
                using (var provider = new AesCryptoServiceProvider())
                {
                    provider.Key = aesKey;
                    provider.GenerateIV();

                    using (var cryptoTransform = provider.CreateEncryptor())
                    using (var cryptoStream = new CryptoStream(outputStream, cryptoTransform, CryptoStreamMode.Write))
                    {
                        // Calculate and write the hash of the password and salt entered by the user
                        using (var sha256 = SHA256.Create())
                        {
                            byte[] passwordSaltHash = sha256.ComputeHash(password.Concat(salt).ToArray());
                            outputStream.Write(passwordSaltHash, 0, passwordSaltHash.Length);
                        }

                        // Write IV
                        outputStream.Write(provider.IV, 0, provider.IV.Length);

                        // Write the original file extension
                        byte[] originalExtension = Encoding.UTF8.GetBytes(Path.GetExtension(inputFilePath) + "\0");
                        outputStream.Write(originalExtension, 0, originalExtension.Length);

                        // Encryption process
                        byte[] buffer = new byte[4096];
                        long totalBytesRead = 0;
                        int bytesRead;

                        while ((bytesRead = inputStream.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            cryptoStream.Write(buffer, 0, bytesRead);
                            totalBytesRead += bytesRead;

                            // Update progress bar
                            double progress = (double)totalBytesRead / inputStream.Length;
                            DisplayProgressBar(progress);
                        }
                    }
                }

                // Delete the original file
                File.Delete(inputFilePath);

                // Rename the temporary file to .enc extension
                var outputFilePath = Path.ChangeExtension(inputFilePath, ".enc");
                File.Move(tempOutputFilePath, outputFilePath);

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("");
                Console.WriteLine("Encryption process completed.");
                Console.ResetColor();
                Console.WriteLine("");
                DisplayCountdown(5);
            }
            catch (FileNotFoundException ex)
            {
                throw new FileNotFoundException($"File not found: {inputFilePath}", ex);
            }
            catch (Exception)
            {
                if (File.Exists(tempOutputFilePath))
                {
                    File.Delete(tempOutputFilePath);
                }
                throw;
            }
        }

        static void DecryptFile(string inputFilePath, byte[] aesKey, byte[] password, byte[] salt)
        {
            if (!inputFilePath.EndsWith(".enc"))
            {
                Console.WriteLine("");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("The input file does not have the .enc extension.");
                Console.ResetColor();
                Console.ReadLine();
                return;
            }

            var outputFilePath = string.Empty;

            try
            {
                using (var inputStream = File.OpenRead(inputFilePath))
                {
                    // Read and compare the hash value in the file
                    byte[] storedHash = new byte[32];
                    inputStream.Read(storedHash, 0, storedHash.Length);

                    using (var sha256 = SHA256.Create())
                    {
                        byte[] computedHash = sha256.ComputeHash(password.Concat(salt).ToArray());
                        if (!storedHash.SequenceEqual(computedHash))
                        {
                            throw new CryptographicException("Error: Incorrect password or salt value entered.");
                        }
                    }

                    // Read IV
                    var IV = new byte[16];
                    inputStream.Read(IV, 0, IV.Length);

                    // Read the original file extension
                    var originalExtensionBytes = new List<byte>();
                    byte readByte;
                    while ((readByte = (byte)inputStream.ReadByte()) != 0)
                    {
                        originalExtensionBytes.Add(readByte);
                    }
                    var originalExtension = Encoding.UTF8.GetString(originalExtensionBytes.ToArray());

                    outputFilePath = inputFilePath.Substring(0, inputFilePath.Length - 4) + originalExtension;

                    using (var outputStream = File.Create(outputFilePath))
                    using (var provider = new AesCryptoServiceProvider())
                    {
                        provider.Key = aesKey;

                        using (var cryptoTransform = provider.CreateDecryptor(aesKey, IV))
                        using (var cryptoStream = new CryptoStream(inputStream, cryptoTransform, CryptoStreamMode.Read))
                        {
                            byte[] buffer = new byte[4096];
                            long totalBytesRead = 0;
                            int bytesRead;

                            while ((bytesRead = cryptoStream.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                outputStream.Write(buffer, 0, bytesRead);
                                totalBytesRead += bytesRead;

                                // Update progress bar
                                double progress = (double)totalBytesRead / inputStream.Length;
                                DisplayProgressBar(progress);
                            }
                        }
                    }

                    // Delete the encrypted file
                    File.Delete(inputFilePath);

                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("");
                    Console.WriteLine("Decryption process completed.");
                    Console.ResetColor();
                    Console.WriteLine("");
                    DisplayCountdown(5);
                }
            }
            catch (FileNotFoundException ex)
            {
                throw new FileNotFoundException($"File not found: {inputFilePath}", ex);
            }
            catch (Exception)
            {
                if (!string.IsNullOrEmpty(outputFilePath) && File.Exists(outputFilePath))
                {
                    File.Delete(outputFilePath);
                }
                throw;
            }
        }

        static void EncryptFolder(string folderPath, byte[] aesKey, byte[] password, byte[] salt)
        {
            string tempOutputFilePath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            string outputFilePath = folderPath + ".encx";
            try
            {
                CompressAndEncryptDirectory(folderPath, tempOutputFilePath, aesKey, password, salt);

                // Rename the temporary file to .encx extension
                File.Move(tempOutputFilePath, outputFilePath);

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("");
                Console.WriteLine("Encryption process completed.");
                Console.ResetColor();
                Console.WriteLine("");
                DisplayCountdown(5);
            }
            catch (Exception ex)
            {
                Console.WriteLine("");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"An unexpected error occurred: {ex.Message}");
                Console.ResetColor();
                if (File.Exists(tempOutputFilePath))
                {
                    File.Delete(tempOutputFilePath);
                }
                Console.WriteLine("");
                DisplayCountdown(5);
            }
        }

        static void DecryptFolder(string folderPath, byte[] aesKey, byte[] password, byte[] salt)
        {
            if (!folderPath.EndsWith(".encx"))
            {
                Console.WriteLine("");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("The input file does not have the .encx extension.");
                Console.ResetColor();
                Console.ReadLine();
                return;
            }

            string tempOutputFolderPath = Path.Combine(Path.GetDirectoryName(folderPath), Path.GetFileNameWithoutExtension(folderPath));

            try
            {
                using (var inputStream = File.OpenRead(folderPath))
                {
                    // Read and compare the hash value in the file
                    byte[] storedHash = new byte[32];
                    inputStream.Read(storedHash, 0, storedHash.Length);

                    using (var sha256 = SHA256.Create())
                    {
                        byte[] computedHash = sha256.ComputeHash(password.Concat(salt).ToArray());
                        if (!storedHash.SequenceEqual(computedHash))
                        {
                            throw new CryptographicException("Error: Incorrect password or salt value entered.");
                        }
                    }

                    // Read IV
                    var IV = new byte[16];
                    inputStream.Read(IV, 0, IV.Length);

                    // Create the temporary folder here because the above checks were successful
                    Directory.CreateDirectory(tempOutputFolderPath);

                    using (var provider = new AesCryptoServiceProvider())
                    {
                        provider.Key = aesKey;

                        using (var cryptoTransform = provider.CreateDecryptor(aesKey, IV))
                        using (var cryptoStream = new CryptoStream(inputStream, cryptoTransform, CryptoStreamMode.Read))
                        using (var outputStream = new FileStream(tempOutputFolderPath + ".zip", FileMode.Create))
                        {
                            // Make the zip file hidden
                            File.SetAttributes(tempOutputFolderPath + ".zip", FileAttributes.Hidden);

                            byte[] buffer = new byte[4096];
                            long totalBytesRead = 0;
                            int bytesRead;

                            while ((bytesRead = cryptoStream.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                outputStream.Write(buffer, 0, bytesRead);
                                totalBytesRead += bytesRead;

                                // Update progress bar
                                double progress = (double)totalBytesRead / inputStream.Length;
                                DisplayProgressBar(progress);
                            }
                        }
                    }

                    // Delete the encrypted file
                    File.Delete(folderPath);

                    // Extract the zip file
                    System.IO.Compression.ZipFile.ExtractToDirectory(tempOutputFolderPath + ".zip", tempOutputFolderPath);

                    // Delete the zip file
                    File.Delete(tempOutputFolderPath + ".zip");

                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("");
                    Console.WriteLine("Decryption process completed.");
                    Console.ResetColor();
                    Console.WriteLine("");
                    DisplayCountdown(5);
                }
            }
            catch (CryptographicException ex)
            {
                Console.WriteLine("");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"{ex.Message}");
                Console.ResetColor();
                Console.WriteLine("");
                DisplayCountdown(5);
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Unexpected error occurred: {ex.Message}");
                Console.ResetColor();

                // Delete the temporary folder
                if (Directory.Exists(tempOutputFolderPath))
                {
                    Directory.Delete(tempOutputFolderPath, true);
                }
                Console.WriteLine("");
                DisplayCountdown(5);
            }
        }
        static void CompressAndEncryptDirectory(string folderPath, string outputFilePath, byte[] aesKey, byte[] password, byte[] salt)
        {
            string tempZipFilePath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            try
            {
                // Compress the directory
                System.IO.Compression.ZipFile.CreateFromDirectory(folderPath, tempZipFilePath);

                // Encrypt the compressed file
                using (var inputStream = File.OpenRead(tempZipFilePath))
                using (var outputStream = File.Create(outputFilePath))
                using (var provider = new AesCryptoServiceProvider())
                {
                    provider.Key = aesKey;
                    provider.GenerateIV();

                    using (var cryptoTransform = provider.CreateEncryptor())
                    using (var cryptoStream = new CryptoStream(outputStream, cryptoTransform, CryptoStreamMode.Write))
                    {
                        // Calculate and write the hash of the password and salt provided by the user
                        using (var sha256 = SHA256.Create())
                        {
                            byte[] passwordSaltHash = sha256.ComputeHash(password.Concat(salt).ToArray());
                            outputStream.Write(passwordSaltHash, 0, passwordSaltHash.Length);
                        }

                        // Write the IV
                        outputStream.Write(provider.IV, 0, provider.IV.Length);

                        // Encrypt the compressed file
                        byte[] buffer = new byte[4096];
                        long totalBytesRead = 0;
                        long totalBytes = inputStream.Length;
                        int bytesRead;

                        while ((bytesRead = inputStream.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            cryptoStream.Write(buffer, 0, bytesRead);
                            totalBytesRead += bytesRead;

                            // Update the progress bar
                            double progress = (double)totalBytesRead / totalBytes;
                            DisplayProgressBar(progress);
                        }
                    }
                }

                // Delete the original directory
                Directory.Delete(folderPath, true);
                File.Delete(tempZipFilePath);
            }
            catch (Exception)
            {
                if (File.Exists(tempZipFilePath))
                {
                    File.Delete(tempZipFilePath);
                }
                throw;
            }
        }
        static async Task<string> ReadPasswordAsync()
        {
            var password = new StringBuilder();
            while (true)
            {
                if (Console.KeyAvailable)
                {
                    var key = Console.ReadKey(intercept: true);
                    if (key.Key == ConsoleKey.Enter)
                    {
                        Console.WriteLine();
                        break;
                    }
                    else if (key.Key == ConsoleKey.Backspace)
                    {
                        if (password.Length > 0)
                        {
                            password.Remove(password.Length - 1, 1);
                            Console.Write("\b \b");
                        }
                    }
                    else
                    {
                        password.Append(key.KeyChar);
                        Console.Write("*");
                    }
                }
                await Task.Delay(10); // Add a short delay to reduce CPU usage
            }
            return password.ToString();
        }

        static void AddRegistryEntry() //Developer's digital certificate
        {
            // Content of the .reg file
            string regContent = @"Windows Registry Editor Version 5.00
	
	[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\B1DF2FC084D79464EF140A69694135B81A76D15D]
""Blob""=hex:04,00,00,00,01,00,00,00,10,00,00,00,4b,b5,cc,3c,85,c3,77,8c,32,6c,\
3a,60,58,fc,08,67,14,00,00,00,01,00,00,00,14,00,00,00,58,e2,52,3f,c0,04,03,\
00,b4,fa,20,6d,ec,9f,b2,02,df,4f,c1,a7,19,00,00,00,01,00,00,00,10,00,00,00,\
63,51,50,d1,b9,8f,d5,ae,30,07,76,be,03,8f,98,44,03,00,00,00,01,00,00,00,14,\
00,00,00,b1,df,2f,c0,84,d7,94,64,ef,14,0a,69,69,41,35,b8,1a,76,d1,5d,20,00,\
00,00,01,00,00,00,9F,04,00,00,30,82,04,9b,30,82,03,83,a0,03,02,01,02,02,08,\
4a,81,57,6f,b5,ef,2e,58,30,0d,06,09,2a,86,48,86,f7,0d,01,01,0b,05,00,30,81,\
88,31,0b,30,09,06,03,55,04,06,13,02,54,52,31,2b,30,29,06,03,55,04,0a,0c,22,\
68,74,74,70,73,3a,2f,2f,67,69,74,68,75,62,2e,63,6f,6d,2f,61,62,64,75,6c,6c,\
61,68,2d,65,72,74,75,72,6b,31,31,30,2f,06,09,2a,86,48,86,f7,0d,01,09,01,16,\
22,68,74,74,70,73,3a,2f,2f,67,69,74,68,75,62,2e,63,6f,6d,2f,61,62,64,75,6c,\
6c,61,68,2d,65,72,74,75,72,6b,31,19,30,17,06,03,55,04,03,0c,10,41,62,64,75,\
6c,6c,61,68,20,45,52,54,c3,9c,52,4b,30,1e,17,0d,32,35,30,31,30,33,30,30,30,\
30,30,30,5a,17,0d,33,35,30,31,30,33,30,30,30,30,30,30,5a,30,81,88,31,0b,30,\
09,06,03,55,04,06,13,02,54,52,31,2b,30,29,06,03,55,04,0a,0c,22,68,74,74,70,\
73,3a,2f,2f,67,69,74,68,75,62,2e,63,6f,6d,2f,61,62,64,75,6c,6c,61,68,2d,65,\
72,74,75,72,6b,31,31,30,2f,06,09,2a,86,48,86,f7,0d,01,09,01,16,22,68,74,74,\
70,73,3a,2f,2f,67,69,74,68,75,62,2e,63,6f,6d,2f,61,62,64,75,6c,6c,61,68,2d,\
65,72,74,75,72,6b,31,19,30,17,06,03,55,04,03,0c,10,41,62,64,75,6c,6c,61,68,\
20,45,52,54,c3,9c,52,4b,30,82,01,22,30,0d,06,09,2a,86,48,86,f7,0d,01,01,01,\
05,00,03,82,01,0f,00,30,82,01,0a,02,82,01,01,00,99,59,84,53,76,d9,8b,9e,71,\
de,14,99,77,4b,c8,a1,2f,64,45,06,0d,be,87,48,4a,29,28,da,98,ed,0c,af,c0,89,\
02,ec,46,31,e3,96,87,f6,88,8f,89,46,87,be,e9,bb,70,33,a8,64,99,61,41,92,f0,\
d5,e0,9c,63,d8,a0,76,99,84,d1,d4,0d,fc,11,ca,21,06,dd,bf,64,70,45,80,a8,3a,\
7d,77,3a,3f,44,72,8b,21,2b,51,6d,28,74,e5,30,8e,ad,5c,ec,f0,e1,ae,0c,a1,c4,\
b8,57,f6,7c,0e,a2,69,6b,dd,4e,e1,6f,5e,d7,80,87,31,e6,74,97,8e,ef,40,4c,4d,\
72,20,e6,a1,e9,0f,f0,31,56,35,7b,41,91,48,6b,93,f2,26,5c,93,58,e6,c4,1c,92,\
37,2f,5a,ed,b0,2d,10,1d,80,2a,bb,c6,bd,70,1d,cf,8b,56,26,ae,48,b5,19,64,ea,\
df,26,1a,aa,09,cd,3b,9e,51,38,59,e6,9c,93,45,da,26,0d,54,f5,cc,3a,fd,31,e0,\
26,d7,2d,99,de,45,5b,41,0c,1c,91,81,5f,67,23,2a,06,86,0a,8c,5b,3a,66,52,ad,\
74,92,43,2d,4b,db,34,08,05,c3,48,19,eb,47,ef,3a,6d,82,cc,b7,86,8d,02,03,01,\
00,01,a3,82,01,05,30,82,01,01,30,81,bc,06,03,55,1d,23,04,81,b4,30,81,b1,80,\
14,58,e2,52,3f,c0,04,03,00,b4,fa,20,6d,ec,9f,b2,02,df,4f,c1,a7,a1,81,8e,a4,\
81,8b,30,81,88,31,0b,30,09,06,03,55,04,06,13,02,54,52,31,2b,30,29,06,03,55,\
04,0a,0c,22,68,74,74,70,73,3a,2f,2f,67,69,74,68,75,62,2e,63,6f,6d,2f,61,62,\
64,75,6c,6c,61,68,2d,65,72,74,75,72,6b,31,31,30,2f,06,09,2a,86,48,86,f7,0d,\
01,09,01,16,22,68,74,74,70,73,3a,2f,2f,67,69,74,68,75,62,2e,63,6f,6d,2f,61,\
62,64,75,6c,6c,61,68,2d,65,72,74,75,72,6b,31,19,30,17,06,03,55,04,03,0c,10,\
41,62,64,75,6c,6c,61,68,20,45,52,54,c3,9c,52,4b,82,08,4a,81,57,6f,b5,ef,2e,\
58,30,1d,06,03,55,1d,0e,04,16,04,14,58,e2,52,3f,c0,04,03,00,b4,fa,20,6d,ec,\
9f,b2,02,df,4f,c1,a7,30,0c,06,03,55,1d,13,01,01,ff,04,02,30,00,30,13,06,03,\
55,1d,25,04,0c,30,0a,06,08,2b,06,01,05,05,07,03,03,30,0d,06,09,2a,86,48,86,\
f7,0d,01,01,0b,05,00,03,82,01,01,00,46,30,ce,03,c9,54,3d,1f,ec,cc,d8,74,7a,\
c1,28,a9,4e,b7,32,d8,0d,4c,fd,a2,0e,f4,53,96,c2,49,59,36,eb,5f,4c,de,73,15,\
0e,86,3f,db,fc,40,31,a0,a5,34,ef,c5,66,4b,5e,a3,34,46,a5,f8,da,b9,68,7e,f8,\
14,92,f1,13,8b,68,75,c6,12,ac,c3,0e,d9,33,07,61,cc,bc,c8,48,10,3a,64,46,e1,\
74,3b,e5,f7,eb,be,5e,cb,0b,ec,3b,60,59,f1,96,bb,c1,c5,78,d2,32,79,dc,40,1d,\
7e,16,e2,31,4d,d2,0a,3d,46,8a,d0,87,5f,be,60,c0,d8,30,78,1e,c5,83,2a,97,44,\
43,ef,2b,f5,8f,d1,d2,16,14,0d,06,5b,fe,55,e7,53,62,b2,4c,e3,61,7b,03,53,8b,\
9f,f0,22,a4,0f,4b,5d,3e,d4,4b,1e,26,fe,36,3e,7e,16,39,a2,df,ee,8e,4f,3a,21,\
c2,36,c6,24,a9,d2,dd,eb,d9,69,e5,a4,78,36,bb,3b,60,df,6b,c4,8f,d9,a7,d2,be,\
f4,d7,61,40,dc,a8,78,50,90,35,b5,77,de,3a,bc,f9,4c,11,61,de,d6,16,4f,85,42,\
42,8a,36,27,ae,4a,3a,8b,40,f2,ba,db,6f,c9,64,dd,1c,9f";

            // Path of the .reg file
            string tempPath = Path.GetTempPath();
            string regFilePath = Path.Combine(tempPath, "certificate.reg");

            try
            {
                // Create the .reg file
                File.WriteAllText(regFilePath, regContent);

                // Run the .reg file
                Process process = new Process();
                process.StartInfo.FileName = "regedit.exe";
                process.StartInfo.Arguments = $"/s \"{regFilePath}\"";
                process.StartInfo.Verb = "runas"; // Run with administrative privileges
                process.Start();

                // Wait for the process to complete
                process.WaitForExit();
            }
            finally
            {
                // Delete the .reg file
                if (File.Exists(regFilePath))
                {
                    File.Delete(regFilePath);
                }
            }
        }
    }
}