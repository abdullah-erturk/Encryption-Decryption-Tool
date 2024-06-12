using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Microsoft.Win32;

namespace Encryption
{
    class CryptWork
    {
        static void Main(string[] args)
        {
            Console.Title = "Encryption / Decryption Tool | made by Abdullah ERTÜRK";

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
                HandleDragAndDrop(inputFilePath);
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
            var passwordInput = Console.ReadLine();
            var password = Encoding.UTF8.GetBytes(passwordInput);

            byte[] key = GenerateKey(password);

            byte[] aesKey = new byte[16];
            Array.Copy(key, aesKey, 16);

            try
            {
                if (mode == "-e")
                {
                    EncryptFile(inputFilePathWithMode, aesKey);
                }
                else if (mode == "-d")
                {
                    DecryptFile(inputFilePathWithMode, aesKey);
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
                Thread.Sleep(3000);
                Environment.Exit(1);
            }
            catch (CryptographicException)
            {
                Console.WriteLine("");
                Console.WriteLine("Hata: Yanlış parola girdiniz.");
                Console.WriteLine("");
                Console.WriteLine("3 saniye içinde otomatik kapanacak.");
                Thread.Sleep(3000);
                Environment.Exit(1);
            }
            catch (Exception ex)
            {
                Console.WriteLine("");
                Console.WriteLine($"Beklenmeyen bir hata oluştu: {ex.Message}");
                Console.WriteLine("");
                Console.WriteLine("3 saniye içinde otomatik kapanacak.");
                Thread.Sleep(3000);
                Environment.Exit(1);
            }
        }

        static void HandleDragAndDrop(string inputFilePath)
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
            var passwordInput = Console.ReadLine();
            var password = Encoding.UTF8.GetBytes(passwordInput);

            byte[] key = GenerateKey(password);

            byte[] aesKey = new byte[16];
            Array.Copy(key, aesKey, 16);

            try
            {
                if (inputFilePath.EndsWith(".enc"))
                {
                    DecryptFile(inputFilePath, aesKey);
                }
                else
                {
                    EncryptFile(inputFilePath, aesKey);
                }
            }
            catch (FileNotFoundException ex)
            {
                Console.WriteLine("");
                Console.WriteLine($"Hata: Dosya bulunamadı. {ex.Message}");
                Console.WriteLine("");
                Console.WriteLine("3 saniye içinde otomatik kapanacak.");
                Thread.Sleep(3000);
                Environment.Exit(1);
            }
            catch (CryptographicException)
            {
                Console.WriteLine("");
                Console.WriteLine("Hata: Yanlış parola girdiniz.");
                Console.WriteLine("");
                Console.WriteLine("3 saniye içinde otomatik kapanacak.");
                Thread.Sleep(3000);
                Environment.Exit(1);
            }
            catch (Exception ex)
            {
                Console.WriteLine("");
                Console.WriteLine($"Beklenmeyen bir hata oluştu: {ex.Message}");
                Console.WriteLine("");
                Console.WriteLine("3 saniye içinde otomatik kapanacak.");
                Thread.Sleep(3000);
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
                    key.SetValue("MUIVerb", "Dosya Şifrelemesi Kaldır");
                    key.SetValue("Icon", @"C:\Windows\system32\imageres.dll,77");
                }

                using (RegistryKey key = Registry.ClassesRoot.CreateSubKey(@".enc\shell\Decrypt File\command"))
                {
                    key.SetValue("", $"\"{destinationFilePath}\" -d \"%1\"");
                }

                Console.WriteLine("");
                Console.WriteLine("Program başarıyla yüklendi ve kayıt defteri girdileri oluşturuldu.");
                Console.WriteLine("");
                Console.WriteLine("Çıkış için herhangi bir tuşa basın.");
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

        static byte[] GenerateKey(byte[] password)
        {
            using (var sha = SHA512.Create())
            {
                byte[] key = sha.ComputeHash(password);
                return sha.ComputeHash(key);
            }
        }

        static void ShowUsage()
        {
            Console.WriteLine("");
            Console.WriteLine("Encryption / Decryption Tool ");
            Console.WriteLine("");
            Console.WriteLine("https://github.com/abdullah-erturk");
            Console.WriteLine("");
            Console.WriteLine("Windows ortamında herhangi bir dosyayı belirlediğiniz parola ile şifreleyin veya şifresini çözün.");
            Console.WriteLine("");
            Console.WriteLine("");
            Console.WriteLine("{0,-15}Programı Windows dizinine yükler ve sağ tık kayıt defteri girdilerini oluşturur.", "-i");
            Console.WriteLine("{0,-15}Programı Windows dizininden kaldırır ve sağ tık kayıt defteri girdilerini siler.", "-u");
            Console.WriteLine("");
            Console.WriteLine("{0,-15}encrypt -i", "yükle    :");
            Console.WriteLine("{0,-15}encrypt -u", "kaldır   :");
            Console.WriteLine("");

            Console.WriteLine("Programı kurmak ister misiniz? (e/h)");
            Console.WriteLine("");

            Console.Write("Seçiminiz: ");
            string cevap = Console.ReadLine();

            if (cevap.ToLower() == "e")
            {
                InstallProgram();
            }

            else if (cevap.ToLower() == "h")
            {
                Console.WriteLine("");
                Console.WriteLine("Program kurulumu iptal edildi.");
                Console.WriteLine("");
                Console.WriteLine("Çıkış için herhangi bir tuşa basın.");
            }
            else
            {
                Console.WriteLine("");
                Console.WriteLine("Geçersiz seçenek! Lütfen 'e' veya 'h' girin.");
                Console.WriteLine("");
                Console.WriteLine("Tekrar denemek için herhangi bir tuşa basın.");
                Console.ReadLine();
                Console.Clear();
                ShowUsage();
            }

        }

        static void EncryptFile(string inputFilePath, byte[] aesKey)
        {
            var outputFilePath = inputFilePath + ".enc";
            try
            {
                using (var inputStream = File.OpenRead(inputFilePath))
                using (var outputStream = File.Create(outputFilePath))
                using (var provider = new AesCryptoServiceProvider())
                {
                    provider.Key = aesKey;
                    provider.GenerateIV();

                    using (var cryptoTransform = provider.CreateEncryptor())
                    using (var cryptoStream = new CryptoStream(outputStream, cryptoTransform, CryptoStreamMode.Write))
                    {
                        outputStream.Write(provider.IV, 0, provider.IV.Length);
                        inputStream.CopyTo(cryptoStream);
                    }
                }
                File.Delete(inputFilePath);
                Environment.Exit(0);
            }
            catch (FileNotFoundException ex)
            {
                throw new FileNotFoundException($"Dosya bulunamadı: {inputFilePath}", ex);
            }
            catch (Exception)
            {
                if (File.Exists(outputFilePath))
                {
                    File.Delete(outputFilePath);
                }
                throw;
            }
        }

        static void DecryptFile(string inputFilePath, byte[] aesKey)
        {
            if (!inputFilePath.EndsWith(".enc"))
            {
                Console.WriteLine("");
                Console.WriteLine("Giriş dosyasının uzantısı .enc değil.");
                Console.ReadLine();
                return;
            }

            var outputFilePath = inputFilePath.Substring(0, inputFilePath.Length - 4);
            try
            {
                using (var inputStream = File.OpenRead(inputFilePath))
                using (var outputStream = File.Create(outputFilePath))
                using (var provider = new AesCryptoServiceProvider())
                {
                    provider.Key = aesKey;

                    var IV = new byte[provider.IV.Length];
                    inputStream.Read(IV, 0, IV.Length);
                    using (var cryptoTransform = provider.CreateDecryptor(aesKey, IV))
                    using (var cryptoStream = new CryptoStream(inputStream, cryptoTransform, CryptoStreamMode.Read))
                    {
                        cryptoStream.CopyTo(outputStream);
                    }
                }
                File.Delete(inputFilePath);
                Environment.Exit(0);
            }
            catch (FileNotFoundException ex)
            {
                throw new FileNotFoundException($"Dosya bulunamadı: {inputFilePath}", ex);
            }
            catch (Exception)
            {
                if (File.Exists(outputFilePath))
                {
                    File.Delete(outputFilePath);
                }
                throw;
            }
        }
    }
}
