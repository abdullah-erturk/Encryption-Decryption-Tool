# Encryption / Decryption Tool
### Encryption / Decryption Tool

     Türkçe Açıklama

Bu C# programı, dosya şifreleme ve şifre çözme işlemlerini kolaylıkla gerçekleştirmenizi sağlar. Dosyalarınızı güvenle şifreleyebilir ve ihtiyaç duyduğunuzda şifresini çözebilirsiniz.

### ÖZELLİKLER:

Dosya uzantı ve boyut kısıtlaması olmadan her türlü dosya şifrelenir.

Kullanıcılar kendi belirledikleri parolalarla dosyalarını şifreleyip çözebilirler.

Program, Advanced Encryption Standard (AES) algoritmasıyla güçlü bir şekilde şifreleme işlemi gerçekleştirir.


### KULLANIM:

Programın 2 tür kullanım yöntemi vardır.

#### Birinci yöntem (kurulum):
Programı çalıştırın, konsol ekranında programın kurulumu ile ilgili gelecek soruya "evet" cevabı verin.

Kurulum kısa sürede tamamlanacaktır.

Artık Windows ortamında her türlü dosyanızda sağ tıkladığınızda "Dosya Şifrele" ve şifrelenmiş dosyalar için de "Dosya Şifrelemesi Kaldır" seçenekleri ile kullanabilirsiniz.

#### İkinci yöntem (sürükle-bırak-şifrele/şifre çöz):
Herhangi bir unzatıya sahip dosyayı encrypt.exe dosyasının üzerine sürükleyip bırakın, bir konsol ekranı açılacak ve şifre belirlemenizi isteyecektir.

Şifrelenmiş bir dosyanın şifresini çözmek için .enc uzantılı dosyayı encrypt.exe dosyasının üzerine sürükleyip bırakın ve önceden belirlediğiniz şifreyi girin.

### ÖNEMLİ NOTLAR:

Parolayı unutmanız durumunda şifreli dosyalarınızı bir daha açamazsınız. Bu nedenle parolanızı güvenli bir şekilde saklamanız önemlidir.

Program, dosya uzantı ve boyut kısıtlaması olmaksızın her türlü dosyayı şifreleyebilir. Yüksek boyutlu dosyaların şifrelenme işlemi uzun sürebilir. 5 GB'lık bir dosyanın şifreleme süresi yaklaşık 30 saniyedir. Elbette bu süre bilgisayarınızın donanım gücüne göre değişecektir.

Şifrelenmiş dosyaların orijinal uzantısı şifreleme esnasında korunmaktadır. Örneğin test.txt dosyasını şifrelediğinizde dosyanın yeni uzantısı .enc unzantısı ile birlitek test.txt.enc olacaktır.

Program tamamen açık kaynak kodludur. Repodan indirip Visual Studio ile istediğiniz değişiklikleri yaparak derleyip kullanabilirsiniz.


     English Explanation

### FEATURES:

All types of files are encrypted without file extension and size restrictions.

Users can encrypt and decrypt their files with passwords they specify.

The program performs a strong encryption process with the Advanced Encryption Standard (AES) algorithm.

### USAGE:

There are 2 types of usage methods for the program.

#### First method (installation):
Run the program, answer "yes" to the question about the installation of the program on the console screen.

The installation will be completed in a short time.

Now, when you right-click on any file in the Windows environment, you can use it with the "Encrypt File" option and for encrypted files, with the "Remove File Encryption" option.

#### Second method (drag-drop-encrypt/decrypt):
Drag and drop any file with any extension onto the encrypt.exe file, a console screen will open and ask you to specify a password.

To decrypt an encrypted file, drag and drop the .enc file onto the encrypt.exe file and enter the password you specified before.

### IMPORTANT NOTES:

If you forget the password, you cannot open your encrypted files again. Therefore, it is important to keep your password securely.

The program can encrypt all types of files without file extension and size restrictions. The encryption process of large files may take a long time. The encryption time for a 5 GB file is approximately 30 seconds. Of course, this time will vary depending on the hardware power of your computer.

The original extension of the encrypted files is protected during encryption. For example, when you encrypt the test.txt file, the new extension of the file will be test.txt.enc with the .enc extension.

The program is completely open source. You can download it from the repo, compile it with Visual Studio and use it by making the changes you want.
