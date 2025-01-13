<a href="https://buymeacoffee.com/abdullaherturk" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>

### Encryption / Decryption Tool v4

![sample](https://github.com/abdullah-erturk/Encryption-Decryption-Tool/blob/main/preview.gif)




     Türkçe Açıklama

<details>

### DİKKAT: v1 ile şifrelediğiniz bir dosyanın şifresini v2 - v3 - v4 ile çözemezsiniz. Önleminizi alın.


Bu program dosya şifreleme ve şifre çözme işlemlerini kolaylıkla gerçekleştirmenizi sağlar. Dosyalarınızı güvenle şifreleyebilir ve ihtiyaç duyduğunuzda şifresini çözebilirsiniz.

Virustotal Raporu:
https://www.virustotal.com/gui/file/824049eef4260912aaf7f98d9f38adef87672e96d8927e6a2de8eee4845a2962


### ÖZELLİKLER:

• AES-256 Şifreleme: Güvenli dosya şifreleme algoritması.

• Komut Satırı Kullanımı: Hızlı ve etkili işlem.

• Sağ Tık Menüsü Entegrasyonu: Dosyaları sağ tık menüsü aracılığıyla kolayca şifreleyin ya da şifrelerini çözün.

• Kullanıcıdan Alınan Parola ve Salt Değeri: Güvenliği artırır.

• Hata Yönetimi: Eksik dosya, yanlış parola veya salt gibi durumların ele alınması.

• Program taşınabilirdir, x bilgisayarında şifrelenmiş bir dosyanın/klasörün y bilgisayarında tekrardan şifresi çözülebilir.

• Şifreli dosyanın uzantısı .enc uzantısıdır.

• Şifreli klasörün uzantısı .encx uzantısıdır.


### KULLANIM:

Programın 2 tür kullanım yöntemi vardır.

#### Birinci yöntem (kurulum):
Programı çalıştırın, konsol ekranında programın kurulumu ile ilgili gelecek soruya "evet" cevabı verin.

Kurulum kısa sürede tamamlanacaktır.

Artık Windows ortamında her türlü dosya ve klasör üzerinde sağ tıkladığınızda dosyalar için 

"Dosya Şifrele" ve şifrelenmiş dosyalar için de "Dosya Şifresini Çöz"
 
ve klasörler için de 

"Klasörü Şifrele" ve şifrelenmiş dosyalar için de "Klasörü Şifresini Çöz" 

seçenekleri ile kullanabilirsiniz.

#### İkinci yöntem (sürükle-bırak-şifrele/şifre çöz):
Herhangi bir uzantıya sahip dosyayı veya klasör encrypt.exe dosyasının üzerine sürükleyip bırakın, bir konsol ekranı açılacak ve şifre ve salt değeri belirlemenizi isteyecektir.

Şifrelenmiş bir dosyanın/klasörün şifresini çözmek için .enc veya .encx uzantılı dosyayı encrypt.exe dosyasının üzerine sürükleyip bırakın ve önceden belirlediğiniz şifreyi ve salt değerini girin.


### NASIL ÇALIŞIR:

• Kullanıcıdan parola ve salt bilgilerin güvenli bir şekilde girilmesi istenir.

• Parola ve salt bilgileri kullanılarak bir AES-256 anahtarı oluşturulur.

• Dosya Şifrelenir.

• Orijinal dosyanın hash değeri hesaplanır ve dosya başına eklenir.

• AES algoritması ile dosya şifrelenir.

• Initialization Vector (IV) ve orijinal dosya uzantısı gibi bilgiler şifreli dosyanın başına eklenir.

• Yeni Dosya Oluşturulur: Şifrelenmiş dosya/klasör .enc veya .encx uzantısı ile kaydedilir ve orijinal dosya silinir.

• Şifreli dosya içeriğinde şifre ve salt bilgisi depolanmaz, sadece kullanıcının girdiği şifre ve salt bilgilerinin hash değeri depolanır.


### ÖNEMLİ NOTLAR:

Parolayı unutmanız durumunda şifreli dosyalarınızı bir daha açamazsınız. Bu nedenle parolanızı güvenli bir şekilde saklamanız önemlidir.

Program, uzantı ve boyut kısıtlaması olmaksızın her türlü dosya ve klasör şifreleyebilir. Yüksek boyutlu dosyaların/klasörlerin şifrelenme işlemi uzun sürebilir. 
5 GB'lık bir dosyanın şifreleme süresi yaklaşık 30 saniyedir. Elbette bu süre bilgisayarınızın donanım gücüne göre değişecektir.

Şifrelenmiş dosyaların orijinal uzantısı şifreleme esnasında kaybolur. Örneğin test.txt dosyasını şifrelediğinizde dosyanın yeni uzantısı .enc uzantısı ile birlite test.enc olacaktır.

Klasör veya dosya fark etmeksizin şifreleme işlemleri C:\ diski üzerinde kısıtlanmıştır. C:\ diski üzerinde sadece masaüstü ve İndirilen klasöründe şifreleme yapılabilir. 
Örnek:
D:\ diskinde bir dosya veya klasör şifrelendi ve bu şifreli dosya/klasör Kullanıcı klasörünün ana dizinine kopyalandı/taşındı. 
Artık o şifreli dosyanın/klasörün şifresi çözülemez, çünkü yasaklı bölgede.

Kullanıcı şifreyi çözmek istediğinde program şu uyarıyı verir:

DİKKAT: Bu klasör/dosya işletim sistemi tarafından kullanılan kritik sistem klasörüdür/dosyasıdır, şifreleme yapılamaz.

Bu kısıtlamanın amacı, acemi kullanıcıların işletim sistemi tarafından kullanılan klasör ve dosyaları yanlışlıkla şifrelemesinin önüne geçmektir.

C:\ diskinin ana dizininde şifreleme ve şifre çözme işlemleri yapılabilir ama işletim sisteminin kullandığı klasörler ve o klasörlerin içindeki diğer 
klasör ve dosyalarda program tarafından şifreleme işlemleri engellenir. 

Bu yollar şunlardır:
- `C:\Windows`
- `C:\Windows\System32`
- `C:\Program Files`
- `C:\Program Files (x86)`
- `C:\Users`
- `C:\ProgramData`
- `C:\$RECYCLE.BIN`
- `C:\System Volume Information`
- `C:\Users\<Username>\AppData`
- `C:\Users\<Username>\Documents`

Program tarafından C:\ diski üzerinde şifreleme işlemine izin verilen klasör yolu da şunlardır:
- `C:\Users\<Username>\Downloads`
- `C:\Users\<Username>\Desktop`

Bu dizinler dışında D:\ - E:\ - F:\ vb. diğer disklerde her türlü şifreleme işlemleri yapılabilir.

Program tamamen açık kaynak kodludur. Repodan indirip Visual Studio ile istediğiniz değişiklikleri yaparak derleyip kullanabilirsiniz.

</details>


     English Explanation

<details>


### ATTENTION A file encrypted with v1 cannot be decrypted with v2 - v3 - v4. Take your precautions.


This program allows you to easily perform file encryption and decryption operations. You can securely encrypt your files and decrypt them whenever you need.


Virustotal Report:
https://www.virustotal.com/gui/file/ee4e02361a710afc0defa9ac0dae3758ca3c461b293c43db1996609f413baba4

### FEATURES:
• AES-256 Encryption: Secure file encryption algorithm.

• Command-Line Usage: Fast and efficient operation.

• Right-Click Menu Integration: Easily encrypt or decrypt files via the right-click menu.

• User-Provided Password and Salt Value: Enhances security.

• Error Management: Handles scenarios such as missing files, incorrect passwords, or salts.

• The program is portable, a file/folder encrypted on computer x can be decrypted again on computer y.

• The extension of the encrypted file is .enc.

• The extension of the encrypted folder is .encx.


### USAGE:
The program offers 2 methods of use.

#### First Method (Installation):
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

• A New File is Created: The encrypted file is saved with a .enc extension, and the original file is deleted.

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
- `C:\Windows`
- `C:\Windows\System32`
- `C:\Program Files`
- `C:\Program Files (x86)`
- `C:\Users`
- `C:\ProgramData`
- `C:\$RECYCLE.BIN`
- `C:\System Volume Information`
- `C:\Users\<Username>\AppData`
- `C:\Users\<Username>\Documents`

The folder paths that the program allows to encrypt on the C:\ disk are:
- `C:\Users\<Username>\Downloads`
- `C:\Users\<Username>\Desktop`

Encryption operations can be performed on other disks such as D:\ - E:\ - F:\ etc. in addition to these directories.

The program is completely open source. You can download it from the repo, make the changes you want with Visual Studio, compile it and use it.

</details>
