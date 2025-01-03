using System;
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

            Console.Title = "Encryption / Decryption Tool v2 | made by Abdullah ERTÜRK";

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
                Console.WriteLine($"Hata: Dosya bulunamadı. {inputFilePathWithMode}");
                Console.ReadLine();
                return;
            }

            Console.WriteLine("");
            Console.Write("Lütfen parolayı girin: ");
            var passwordInput = await ReadPasswordAsync();
            var password = Encoding.UTF8.GetBytes(passwordInput);

            Console.WriteLine("");
            Console.Write("Lütfen salt değerini girin: ");
            var saltInput = await ReadPasswordAsync();
            var salt = Encoding.UTF8.GetBytes(saltInput);

            byte[] key = GenerateKey(password, salt);
            byte[] aesKey = new byte[32]; // AES-256 için 32 byte anahtar
            Array.Copy(key, aesKey, 32);

            try
            {
                if (mode == "-e")
                {
                    Console.WriteLine("");
                    Console.WriteLine("Şifreleme işlemi yapılıyor, lütfen bekleyin...");
                    Console.WriteLine("");
                    EncryptFile(inputFilePathWithMode, aesKey, password, salt);
                }
                else if (mode == "-d")
                {
                    Console.WriteLine("");
                    Console.WriteLine("Şifre çözülüyor, lütfen bekleyin...");
                    Console.WriteLine("");
                    DecryptFile(inputFilePathWithMode, aesKey, password, salt);
                }
                else
                {
                    Console.WriteLine("");
                    Console.WriteLine("Şifreleme/şifre çözme modunu -e veya -d ile seçmelisiniz.");
                    Console.ReadLine();
                }
            }
            catch (FileNotFoundException ex)
            {
                Console.WriteLine("");
                Console.WriteLine($"Hata: Dosya bulunamadı. {ex.Message}");
                Console.WriteLine("");
                Console.WriteLine("3 saniye içinde otomatik kapanacak.");
                await Task.Delay(3000);
                Environment.Exit(1);
            }
            catch (CryptographicException)
            {
                Console.WriteLine("");
                Console.WriteLine("Hata: Yanlış parola veya salt değeri girdiniz.");
                Console.WriteLine("");
                Console.WriteLine("3 saniye içinde otomatik kapanacak.");
                await Task.Delay(3000);
                Environment.Exit(1);
            }
            catch (Exception ex)
            {
                Console.WriteLine("");
                Console.WriteLine($"Beklenmeyen bir hata oluştu: {ex.Message}");
                Console.WriteLine("");
                Console.WriteLine("3 saniye içinde otomatik kapanacak.");
                await Task.Delay(3000);
                Environment.Exit(1);
            }
        }

        static async Task HandleDragAndDrop(string inputFilePath)
        {
            if (!File.Exists(inputFilePath))
            {
                Console.WriteLine("");
                Console.WriteLine($"Hata: Dosya bulunamadı. {inputFilePath}");
                Console.ReadLine();
                return;
            }

            Console.WriteLine("");
            Console.Write("Lütfen parolayı girin: ");
            var passwordInput = await ReadPasswordAsync();
            var password = Encoding.UTF8.GetBytes(passwordInput);

            Console.WriteLine("");
            Console.Write("Lütfen salt değerini girin: ");
            var saltInput = await ReadPasswordAsync();
            var salt = Encoding.UTF8.GetBytes(saltInput);

            byte[] key = GenerateKey(password, salt);
            byte[] aesKey = new byte[32]; // AES-256 için 32 byte anahtar
            Array.Copy(key, aesKey, 32);

            try
            {
                if (inputFilePath.EndsWith(".enc"))
                {
                    Console.WriteLine("");
                    Console.WriteLine("Şifre çözülüyor, lütfen bekleyin...");
                    Console.WriteLine("");
                    DecryptFile(inputFilePath, aesKey, password, salt);
                }
                else
                {
                    Console.WriteLine("");
                    Console.WriteLine("Şifreleme işlemi yapılıyor, lütfen bekleyin...");
                    Console.WriteLine("");
                    EncryptFile(inputFilePath, aesKey, password, salt);
                }
            }
            catch (FileNotFoundException ex)
            {
                Console.WriteLine("");
                Console.WriteLine($"Hata: Dosya bulunamadı. {ex.Message}");
                Console.WriteLine("");
                Console.WriteLine("3 saniye içinde otomatik kapanacak.");
                await Task.Delay(3000);
                Environment.Exit(1);
            }
            catch (CryptographicException)
            {
                Console.WriteLine("");
                Console.WriteLine("Hata: Yanlış parola veya salt değeri girdiniz.");
                Console.WriteLine("");
                Console.WriteLine("3 saniye içinde otomatik kapanacak.");
                await Task.Delay(3000);
                Environment.Exit(1);
            }
            catch (Exception ex)
            {
                Console.WriteLine("");
                Console.WriteLine($"Beklenmeyen bir hata oluştu: {ex.Message}");
                Console.WriteLine("");
                Console.WriteLine("3 saniye içinde otomatik kapanacak.");
                await Task.Delay(3000);
                Environment.Exit(1);
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
                    key.SetValue("MUIVerb", "Dosyayı Şifrele");
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
                    key.SetValue("MUIVerb", "Dosya Şifresini Çöz");
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
                Console.WriteLine("Program başarıyla yüklendi ve kayıt defteri girdileri oluşturuldu.");
                Console.WriteLine("");
                Console.WriteLine("Çıkış için ENTER tuşuna basın.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("");
                Console.WriteLine($"Kurulum sırasında bir hata oluştu: {ex.Message}");
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
                Console.WriteLine("Program başarıyla kaldırıldı ve kayıt defteri girdileri silindi.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("");
                Console.WriteLine($"Kaldırma sırasında bir hata oluştu: {ex.Message}");
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
            using (RegistryKey key = Registry.ClassesRoot.CreateSubKey(@".enc\DefaultIcon"))
            {
                key.SetValue("", @"C:\Windows\system32\imageres.dll,54");
            }

            {
                string userProfile = Environment.GetEnvironmentVariable("USERPROFILE");
                string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                string command = $"/c cd /d \"{localAppData}\" & del IconCache.db /a";
                ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", command);
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                Process process = Process.Start(psi);
                process.WaitForExit();
            }

            Console.WriteLine("");
            Console.WriteLine("Encryption / Decryption Tool v2 ");
            Console.WriteLine("");
            Console.WriteLine("https://github.com/abdullah-erturk");
            Console.WriteLine("");
            Console.WriteLine("");
            Console.WriteLine("Windows ortamında herhangi bir dosyayı belirlediğiniz parola ile şifreleyin veya şifresini çözün.");
            Console.WriteLine("");
            Console.WriteLine("");

            string encryptExePath = @"C:\Windows\encrypt.exe";

            if (File.Exists(encryptExePath))
            {
                while (true)
                {
                    Console.WriteLine("Program zaten yüklü. Kaldırmak ister misiniz? (e/h)");
                    Console.WriteLine("");
                    Console.Write("Seçiminiz: ");
                    string cevap = Console.ReadLine();

                    if (cevap.ToLower() == "e")
                    {
                        UninstallProgram();
                        Console.WriteLine("");
                        Console.WriteLine("Çıkış için ENTER tuşuna basın.");
                        break;
                    }
                    else if (cevap.ToLower() == "h")
                    {
                        Console.WriteLine("");
                        Console.WriteLine("Programın kaldırılma işlemi iptal edildi.");
                        Console.WriteLine("");
                        Console.WriteLine("Çıkış için ENTER tuşuna basın.");
                        break;
                    }
                    else
                    {
                        Console.WriteLine("");
                        Console.WriteLine("Geçersiz seçenek! Lütfen 'e' veya 'h' girin.");
                        Console.WriteLine("");
                        Console.WriteLine("Tekrar denemek için ENTER tuşuna basın.");
                        Console.ReadLine();
                    }
                }
            }
            else
            {
                while (true)
                {
                    Console.WriteLine("Programı kurmak ister misiniz? (e/h)");
                    Console.WriteLine("");
                    Console.WriteLine("e = Programı Windows dizinine yükler ve sağ tık kayıt defteri girdilerini oluşturur.");
                    Console.WriteLine("h = Programı Windows dizininden kaldırır ve sağ tık kayıt defteri girdilerini siler.");
                    Console.WriteLine("");
                    Console.Write("Seçiminiz: ");
                    string cevap = Console.ReadLine();

                    if (cevap.ToLower() == "e")
                    {
                        InstallProgram();
                        break;
                    }
                    else if (cevap.ToLower() == "h")
                    {
                        Console.WriteLine("");
                        Console.WriteLine("Program kurulumu iptal edildi.");
                        Console.WriteLine("");
                        Console.WriteLine("Çıkış için ENTER tuşuna basın.");
                        break;
                    }
                    else
                    {
                        Console.WriteLine("");
                        Console.WriteLine("Geçersiz seçenek! Lütfen 'e' veya 'h' girin.");
                        Console.WriteLine("");
                        Console.WriteLine("Tekrar denemek için ENTER tuşuna basın.");
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
                Console.WriteLine("DİKKAT : Dosya zaten şifreli, tekrar şifreleme işlemi yapılamaz.");
                Console.WriteLine("");
                Console.WriteLine("4 saniye içinde otomatik kapanacak.");
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
                        // Kullanıcı tarafından girilen şifre ve salt değerlerinin hash'ini hesapla ve yaz
                        using (var sha256 = SHA256.Create())
                        {
                            byte[] passwordSaltHash = sha256.ComputeHash(password.Concat(salt).ToArray());
                            outputStream.Write(passwordSaltHash, 0, passwordSaltHash.Length);
                        }

                        // IV'yi yaz
                        outputStream.Write(provider.IV, 0, provider.IV.Length);

                        // Orijinal dosya uzantısını yaz
                        byte[] originalExtension = Encoding.UTF8.GetBytes(Path.GetExtension(inputFilePath) + "\0");
                        outputStream.Write(originalExtension, 0, originalExtension.Length);

                        // Şifreleme işlemi
                        inputStream.CopyTo(cryptoStream);
                    }
                }

                // Orijinal dosyayı sil
                File.Delete(inputFilePath);

                // Geçici dosyayı .enc uzantılı olarak yeniden adlandır
                var outputFilePath = Path.ChangeExtension(inputFilePath, ".enc");
                File.Move(tempOutputFilePath, outputFilePath);

                Console.WriteLine("Şifreleme işlemi tamamlandı.");
                Console.WriteLine("");
                Console.WriteLine("3 saniye içinde otomatik kapanacak.");
                Thread.Sleep(3000);
                Environment.Exit(0);
            }
            catch (FileNotFoundException ex)
            {
                throw new FileNotFoundException($"Dosya bulunamadı: {inputFilePath}", ex);
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
                Console.WriteLine("Giriş dosyasının uzantısı .enc değil.");
                Console.ReadLine();
                return;
            }

            var outputFilePath = string.Empty;

            try
            {
                using (var inputStream = File.OpenRead(inputFilePath))
                {
                    // Dosyadaki hash değerini okuma ve karşılaştırma
                    byte[] storedHash = new byte[32];
                    inputStream.Read(storedHash, 0, storedHash.Length);

                    using (var sha256 = SHA256.Create())
                    {
                        byte[] computedHash = sha256.ComputeHash(password.Concat(salt).ToArray());
                        if (!storedHash.SequenceEqual(computedHash))
                        {
                            throw new CryptographicException("Hata: Yanlış parola veya salt değeri girdiniz.");
                        }
                    }

                    // IV'yi okuma
                    var IV = new byte[16];
                    inputStream.Read(IV, 0, IV.Length);

                    // Orijinal dosya uzantısını okuma
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

                    // Şifreli dosyayı sil
                    File.Delete(inputFilePath);

                    Console.WriteLine("Şifre çözme işlemi tamamlandı.");
                    Console.WriteLine("");
                    Console.WriteLine("3 saniye içinde otomatik kapanacak.");
                    Thread.Sleep(3000);
                    Environment.Exit(0);
                }
            }
            catch (FileNotFoundException ex)
            {
                throw new FileNotFoundException($"Dosya bulunamadı: {inputFilePath}", ex);
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
                        Console.Write(key.KeyChar);
                        await Task.Delay(240);
                        Console.Write("\b \b*");
                    }
                }
                await Task.Delay(10); // Kısa bir bekleme süresi ekleyerek CPU kullanım
            }
            return password.ToString();
        }
    }
}