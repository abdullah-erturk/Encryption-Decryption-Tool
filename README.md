<a href="https://buymeacoffee.com/abdullaherturk" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>

# Encryption / Decryption Tool v3


![sample](https://github.com/abdullah-erturk/Encryption-Decryption-Tool/blob/main/preview.gif)



### Encryption / Decryption Tool v3

     Türkçe Açıklama

<details>

### DİKKAT: v1 ile şifrelediğiniz bir dosyanın şifresini v2 ve v3 ile çözemezsiniz. Önleminizi alın.


Bu program dosya şifreleme ve şifre çözme işlemlerini kolaylıkla gerçekleştirmenizi sağlar. Dosyalarınızı güvenle şifreleyebilir ve ihtiyaç duyduğunuzda şifresini çözebilirsiniz.


Virustotal Raporu:
https://www.virustotal.com/gui/file/3dea2b5b24c4804e6d2e89443c022f99db9dcd6c836d5cb88f7d3f82f1b65f35


### ÖZELLİKLER:

•	AES-256 Şifreleme: Güvenli dosya şifreleme algoritması.

•	Komut Satırı Kullanımı: Hızlı ve etkili işlem.

•	Sağ Tık Menüsü Entegrasyonu: Dosyaları sağ tık menüsü aracılığıyla kolayca şifreleyin ya da şifrelerini çözün.

•	Kullanıcıdan Alınan Parola ve Salt Değeri: Güvenliği artırır.

•	Hata Yönetimi: Eksik dosya, yanlış parola veya salt gibi durumların ele alınması.


### KULLANIM:

Programın 2 tür kullanım yöntemi vardır.

#### Birinci yöntem (kurulum):
Programı çalıştırın, konsol ekranında programın kurulumu ile ilgili gelecek soruya "evet" cevabı verin.

Kurulum kısa sürede tamamlanacaktır.

Artık Windows ortamında her türlü dosyanızda sağ tıkladığınızda "Dosya Şifrele" ve şifrelenmiş dosyalar için de "Dosya Şifresini Çöz" seçenekleri ile kullanabilirsiniz.

#### İkinci yöntem (sürükle-bırak-şifrele/şifre çöz):
Herhangi bir uzantıya sahip dosyayı encrypt.exe dosyasının üzerine sürükleyip bırakın, bir konsol ekranı açılacak ve şifre ve salt değeri belirlemenizi isteyecektir.

Şifrelenmiş bir dosyanın şifresini çözmek için .enc uzantılı dosyayı encrypt.exe dosyasının üzerine sürükleyip bırakın ve önceden belirlediğiniz şifreyi ve salt değerini girin.

### NASIL ÇALIŞIR:

•	Kullanıcıdan parola ve salt bilgilerin güvenli bir şekilde girilmesi istenir.

•	Parola ve salt bilgileri kullanılarak bir AES-256 anahtarı oluşturulur.

•	Dosya Şifrelenir.

•	Orijinal dosyanın hash değeri hesaplanır ve dosya başına eklenir.

•	AES algoritması ile dosya şifrelenir.

•	Initialization Vector (IV) ve orijinal dosya uzantısı gibi bilgiler şifreli dosyanın başına eklenir.

•	Yeni Dosya Oluşturulur: Şifrelenmiş dosya .enc uzantısı ile kaydedilir ve orijinal dosya silinir.

•	Şifreli dosya içeriğinde şifre ve salt bilgisi depolanmaz, sadece kullanıcının girdiği şifre ve salt bilgilerinin hash değeri depolanır.

### ÖNEMLİ NOTLAR:

Parolayı unutmanız durumunda şifreli dosyalarınızı bir daha açamazsınız. Bu nedenle parolanızı güvenli bir şekilde saklamanız önemlidir.

Program, dosya uzantı ve boyut kısıtlaması olmaksızın her türlü dosyayı şifreleyebilir. Yüksek boyutlu dosyaların şifrelenme işlemi uzun sürebilir. 5 GB'lık bir dosyanın şifreleme süresi yaklaşık 30 saniyedir. Elbette bu süre bilgisayarınızın donanım gücüne göre değişecektir.

Şifrelenmiş dosyaların orijinal uzantısı şifreleme esnasında kaybolur. Örneğin test.txt dosyasını şifrelediğinizde dosyanın yeni uzantısı .enc unzantısı ile birlite test.enc olacaktır.

Program tamamen açık kaynak kodludur. Repodan indirip Visual Studio ile istediğiniz değişiklikleri yaparak derleyip kullanabilirsiniz.

</details>


     English Explanation

<details>


### ATTENTION A file encrypted with v1 cannot be decrypted with v2 and v3. Take your precautions.



This program allows you to easily perform file encryption and decryption operations. You can securely encrypt your files and decrypt them whenever you need.


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

</details>
