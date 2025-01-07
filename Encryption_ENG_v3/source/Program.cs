using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace Encryption
{
    class CryptWork
    {
        static async Task Main(string[] args)
        {
            int width = 98;
            int height = 20;

            Console.SetWindowSize(width, height);
            Console.SetBufferSize(width, height);

            Console.Title = "Encryption / Decryption Tool v3 | made by Abdullah ERTÜRK";

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

            if (!File.Exists(inputFilePathWithMode))
            {
                Console.WriteLine("");
                Console.WriteLine($"Error: File not found. {inputFilePathWithMode}");
                Console.ReadLine();
                return;
            }

            if (mode == "-e" && inputFilePathWithMode.EndsWith(".enc"))
            {
                Console.WriteLine("");
                Console.WriteLine("WARNING: The file is already encrypted, encryption cannot be done again.");
                Console.WriteLine("");
                Console.WriteLine("The program will close automatically in 4 seconds.");
                await Task.Delay(4000);
                Environment.Exit(0);
            }

            Console.WriteLine("");
            Console.WriteLine($"Processing file: {inputFilePathWithMode}");
            Console.WriteLine("");
            Console.Write("Please enter the password: ");
            var passwordInput = await ReadPasswordAsync();
            var password = Encoding.UTF8.GetBytes(passwordInput);

            Console.WriteLine("");
            Console.Write("Please enter the salt value: ");
            var saltInput = await ReadPasswordAsync();
            var salt = Encoding.UTF8.GetBytes(saltInput);

            byte[] key = GenerateKey(password, salt);
            byte[] aesKey = new byte[32]; // 32 bytes for AES-256 key
            Array.Copy(key, aesKey, 32);

            try
            {
                if (mode == "-e")
                {
                    Console.WriteLine("");
                    Console.WriteLine("Encrypting, please wait...");
                    Console.WriteLine("");
                    EncryptFile(inputFilePathWithMode, aesKey, password, salt);
                }
                else if (mode == "-d")
                {
                    Console.WriteLine("");
                    Console.WriteLine("Decrypting, please wait...");
                    Console.WriteLine("");
                    DecryptFile(inputFilePathWithMode, aesKey, password, salt);
                }
                else
                {
                    Console.WriteLine("");
                    Console.WriteLine("You must select encryption/decryption mode with -e or -d.");
                    Console.ReadLine();
                }
            }
            catch (FileNotFoundException ex)
            {
                Console.WriteLine("");
                Console.WriteLine($"Error: File not found. {ex.Message}");
                Console.WriteLine("");
                Console.WriteLine("The program will close automatically in 3 seconds.");
                await Task.Delay(3000);
                Environment.Exit(1);
            }
            catch (CryptographicException)
            {
                Console.WriteLine("");
                Console.WriteLine("Error: You entered an incorrect password or salt value.");
                Console.WriteLine("");
                Console.WriteLine("The program will close automatically in 3 seconds.");
                await Task.Delay(3000);
                Environment.Exit(1);
            }
            catch (Exception ex)
            {
                Console.WriteLine("");
                Console.WriteLine($"An unexpected error occurred: {ex.Message}");
                Console.WriteLine("");
                Console.WriteLine("The program will close automatically in 3 seconds.");
                await Task.Delay(3000);
                Environment.Exit(1);
            }
        }

        static async Task HandleDragAndDrop(string inputFilePath)
        {
            if (!File.Exists(inputFilePath))
            {
                Console.WriteLine("");
                Console.WriteLine($"Error: File not found. {inputFilePath}");
                Console.ReadLine();
                return;
            }

            Console.WriteLine("");
            Console.WriteLine($"Processing file: {inputFilePath}");
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
                byte[] aesKey = new byte[32]; // 32 bytes for AES-256 key
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
                    Console.WriteLine($"Error: File not found. {ex.Message}");
                    Console.WriteLine("");
                    Console.WriteLine("The program will close automatically in 3 seconds.");
                    await Task.Delay(3000);
                    Environment.Exit(1);
                }
                catch (CryptographicException)
                {
                    Console.WriteLine("");
                    Console.WriteLine("Error: You entered an incorrect password or salt value.");
                    Console.WriteLine("");
                    Console.WriteLine("The program will close automatically in 3 seconds.");
                    await Task.Delay(3000);
                    Environment.Exit(1);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("");
                    Console.WriteLine($"An unexpected error occurred: {ex.Message}");
                    Console.WriteLine("");
                    Console.WriteLine("The program will close automatically in 3 seconds.");
                    await Task.Delay(3000);
                    Environment.Exit(1);
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
                byte[] aesKey = new byte[32]; // 32 bytes for AES-256 key
                Array.Copy(key, aesKey, 32);

                try
                {
                    Console.WriteLine("");
                    Console.WriteLine("Encrypting, please wait...");
                    Console.WriteLine("");
                    EncryptFile(inputFilePath, aesKey, password, salt);
                }
                catch (FileNotFoundException ex)
                {
                    Console.WriteLine("");
                    Console.WriteLine($"Error: File not found. {ex.Message}");
                    Console.WriteLine("");
                    Console.WriteLine("The program will close automatically in 3 seconds.");
                    await Task.Delay(3000);
                    Environment.Exit(1);
                }
                catch (CryptographicException)
                {
                    Console.WriteLine("");
                    Console.WriteLine("Error: You entered an incorrect password or salt value.");
                    Console.WriteLine("");
                    Console.WriteLine("The program will close automatically in 3 seconds.");
                    await Task.Delay(3000);
                    Environment.Exit(1);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("");
                    Console.WriteLine($"An unexpected error occurred: {ex.Message}");
                    Console.WriteLine("");
                    Console.WriteLine("The program will close automatically in 3 seconds.");
                    await Task.Delay(3000);
                    Environment.Exit(1);
                }
            }
        }

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

                Console.WriteLine("");
                Console.WriteLine("Program successfully installed and registry entries created.");
                Console.WriteLine("");
                Console.WriteLine("Press ENTER to exit.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("");
                Console.WriteLine($"An error occurred during installation: {ex.Message}");
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

                using (RegistryKey key = Registry.ClassesRoot.OpenSubKey(@".enc\shell", true))
                {
                    if (key != null)
                    {
                        key.DeleteSubKeyTree("Decrypt File", false);
                    }
                }

                using (RegistryKey key = Registry.ClassesRoot.OpenSubKey(@".enc", true))
                {
                    if (key != null)
                    {
                        key.DeleteSubKeyTree("", false);
                    }
                }

                Console.WriteLine("");
                Console.WriteLine("Program successfully uninstalled and registry entries deleted.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("");
                Console.WriteLine($"An error occurred during uninstallation: {ex.Message}");
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
            Console.WriteLine("Encryption / Decryption Tool v3 ");
            Console.WriteLine("");
            Console.WriteLine("https://github.com/abdullah-erturk");
            Console.WriteLine("");
            Console.WriteLine("");
            Console.WriteLine("Encrypt or decrypt any file in Windows environment with the password you specify.");
            Console.WriteLine("");
            Console.WriteLine("");

            string encryptExePath = @"C:\Windows\encrypt.exe";

            if (File.Exists(encryptExePath))
            {
                while (true)
                {
                    Console.WriteLine("The program is already installed. Do you want to uninstall it? (y/n)");
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
                        Console.WriteLine("Uninstallation of the program has been canceled.");
                        Console.WriteLine("");
                        Console.WriteLine("Press ENTER to exit.");
                        break;
                    }
                    else
                    {
                        Console.WriteLine("");
                        Console.WriteLine("Invalid option! Please enter 'y' or 'n'.");
                        Console.WriteLine("");
                        Console.WriteLine("Press ENTER to try again.");
                        Console.ReadLine();
                    }
                }
            }
            else
            {
                while (true)
                {
                    Console.WriteLine("Do you want to install the program? (y/n)");
                    Console.WriteLine("");
                    Console.WriteLine("y = Installs the program in the Windows directory and creates right-click registry entries.");
                    Console.WriteLine("n = Uninstalls the program from the Windows directory and deletes the right-click registry entries.");
                    Console.WriteLine("");
                    Console.Write("Your choice: ");
                    string answer = Console.ReadLine();

                    if (answer.ToLower() == "y")
                    {
                        InstallProgram();
                        break;
                    }
                    else if (answer.ToLower() == "n")
                    {
                        Console.WriteLine("");
                        Console.WriteLine("Program installation canceled.");
                        Console.WriteLine("");
                        Console.WriteLine("Press ENTER to exit.");
                        break;
                    }
                    else
                    {
                        Console.WriteLine("");
                        Console.WriteLine("Invalid option! Please enter 'y' or 'n'.");
                        Console.WriteLine("");
                        Console.WriteLine("Press ENTER to try again.");
                        Console.ReadLine();
                        Console.Clear();
                    }
                }
            }
        }

        static void EncryptFile(string inputFilePath, byte[] aesKey, byte[] password, byte[] salt)
        {
            if (inputFilePath.EndsWith(".enc"))
            {
                Console.WriteLine("WARNING: The file is already encrypted, encryption cannot be done again.");
                Console.WriteLine("");
                Console.WriteLine("The program will close automatically in 4 seconds.");
                Thread.Sleep(4000);
                Environment.Exit(0);
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
                        // Calculate and write the hash of the user-entered password and salt values
                        using (var sha256 = SHA256.Create())
                        {
                            byte[] passwordSaltHash = sha256.ComputeHash(password.Concat(salt).ToArray());
                            outputStream.Write(passwordSaltHash, 0, passwordSaltHash.Length);
                        }

                        // Write the IV
                        outputStream.Write(provider.IV, 0, provider.IV.Length);

                        // Write the original file extension
                        byte[] originalExtension = Encoding.UTF8.GetBytes(Path.GetExtension(inputFilePath) + "\0");
                        outputStream.Write(originalExtension, 0, originalExtension.Length);

                        // Encryption process
                        inputStream.CopyTo(cryptoStream);
                    }
                }

                // Delete the original file
                File.Delete(inputFilePath);

                // Rename the temporary file with .enc extension
                var outputFilePath = Path.ChangeExtension(inputFilePath, ".enc");
                File.Move(tempOutputFilePath, outputFilePath);

                Console.WriteLine("Encryption completed.");
                Console.WriteLine("");
                Console.WriteLine("The program will close automatically in 3 seconds.");
                Thread.Sleep(3000);
                Environment.Exit(0);
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
                Console.WriteLine("The input file extension is not .enc.");
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
                            throw new CryptographicException("Error: You entered an incorrect password or salt value.");
                        }
                    }

                    // Read the IV
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
                            cryptoStream.CopyTo(outputStream);
                        }
                    }

                    // Delete the encrypted file
                    File.Delete(inputFilePath);

                    Console.WriteLine("Decryption completed.");
                    Console.WriteLine("");
                    Console.WriteLine("The program will close automatically in 3 seconds.");
                    Thread.Sleep(3000);
                    Environment.Exit(0);
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
                await Task.Delay(10); // Adding a short delay to reduce CPU usage
            }
            return password.ToString();
        }
    }
}