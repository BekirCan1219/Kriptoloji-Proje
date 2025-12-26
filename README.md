👤 Öğrenci Bilgileri
•	Ad Soyad: Bekir Can İmamoğlu
•	Öğrenci Numarası: 436539
•	Bölüm: Yazılım Mühendisliği
•	Ders: Bilgi Güvenliği Ve Kriptoloji
•	Proje Türü: Dönem Projesi
________________________________________
1. Projenin Amacı
Bu projenin amacı, gerçek zamanlı çalışan, farklı kriptografik algoritmaları destekleyen, şifreli mesajlaşma yapabilen bir web uygulaması geliştirmektir.
Uygulama ile:
•	Kullanıcılar sohbet odalarına katılabilir,
•	Mesajlar seçilen kriptografik algoritma ile şifrelenerek gönderilir,
•	Şifreli mesajlar veritabanında güvenli şekilde saklanır,
•	İstenildiğinde mesajlar doğru anahtar ile çözülebilir,
•	Gerçek zamanlı iletişim altyapısı ve şifreleme birlikte kullanılabilir.
________________________________________
2. Kullanılan Teknolojiler
Backend
•	Python
•	Flask
•	Flask-SocketIO
•	SQLAlchemy
•	MSSQL (SQL Server)
Frontend
•	HTML
•	CSS
•	JavaScript
•	Socket.IO Client
Kriptografi
•	Simetrik, asimetrik ve klasik algoritmalar
•	Base64 ve JSON tabanlı veri normalizasyonu
________________________________________
3. Desteklenen Şifreleme Algoritmaları
Projede aşağıdaki algoritmalar aktif olarak entegre edilmiştir:
Simetrik
•	AES-128 CBC
•	DES
•	3DES
•	Blowfish
•	RC2
•	RC5
•	Manual AES
Klasik
•	Caesar Cipher
•	Affine Cipher
•	Vigenere Cipher
•	Hill Cipher
Asimetrik / Modern
•	RSA
•	ElGamal
•	Rabin
•	Knapsack
•	Diffie-Hellman (DH)
•	Elliptic Curve Cryptography (ECC)
•	DSA (Dijital İmza)
________________________________________
4. Sistem Mimarisi
Genel Akış
1.	Kullanıcı giriş yapar.
2.	Bir sohbet odasına katılır.
3.	Mesaj gönderirken bir algoritma ve anahtar seçer.
4.	Mesaj backend’de şifrelenir.
5.	Şifreli veri:
o	Sohbete gönderilir
o	Veritabanına kaydedilir
6.	Mesajlar istenirse çözme panelinden tekrar çözülür.
________________________________________
5. Gerçek Zamanlı Haberleşme (Socket.IO)
Uygulama WebSocket tabanlı Socket.IO kullanmaktadır.
Kullanılan Socket eventleri:
•	join → Odaya katılma
•	chat_message → Şifreli mesaj gönderme
•	history → Oda geçmişini alma
•	decrypt_message → Mesaj çözme
•	decrypt_result → Çözüm sonucu
•	system_message → Sistem olayları (odaya katılma vb.)
________________________________________
6. Ciphertext Normalizasyonu (Önemli Teknik Detay)
Socket.IO üzerinden bazı algoritmalar bytes tipinde çıktı üretmektedir.
Bu durum WebSocket trafiğinde binary frame oluşmasına sebep olmaktadır.
Çözüm Yaklaşımı
Tüm şifreli veriler tek tip JSON wire formatına dönüştürülmüştür:
{
  "encoding": "b64",
  "data": "..."
}
veya
{
  "encoding": "str",
  "data": "..."
}
Veritabanı Saklama Formatı
Veritabanında ciphertext her zaman string olarak tutulur:
•	b64:<base64_data>
•	str:<string_data>
Bu sayede:
•	Binary veri problemi ortadan kaldırılmış,
•	UI, decrypt paneli ve network trafiği uyumlu hale getirilmiştir.
________________________________________
7. Kullanıcı Arayüzü Özellikleri
Sol Panel
•	Oda adı ve kullanıcı bilgisi
•	Algoritma seçimi
•	Anahtar girişi
•	Hill cipher için matris boyutu
•	Şifreli mesaj listesi
•	Mesaj gönderme alanı
Sağ Panel
•	Algoritma seçimi (decrypt)
•	Şifreli metin girişi
•	Anahtar girişi
•	Çözülmüş metin alanı
Ek Özellikler
•	Ciphertext tek tıkla kopyalanabilir
•	Decrypt paneline otomatik aktarılabilir
•	Sistem mesajları (odaya katıldı vb.) ayrı gösterilir
________________________________________
8. Yetkilendirme Sistemi
•	Admin ve normal kullanıcı rolleri vardır.
•	Admin:
o	Mesajları görüntüleyebilir
o	Mesaj silebilir
•	Normal kullanıcı:
o	Sohbet ve şifreleme işlemleri yapabilir
________________________________________
9. Proje Ekleri (Kod İçinden)
Bu projede ek dosya gönderilmemiştir.
Tüm ekler proje içinde yer almaktadır.
•	app.py
→ Backend, Socket.IO eventleri, şifreleme, DB kayıt, wire format
•	static/js/main.js
→ UI, socket eventleri, wire parsing, decrypt akışı
•	templates/index.html
→ Ana sohbet arayüzü
•	templates/login.html
→ Giriş ekranı
________________________________________
10. Sonuç ve Değerlendirme
Bu projede:
•	Gerçek zamanlı web uygulaması geliştirme,
•	Kriptografik algoritmaların pratik kullanımı,
•	Socket.IO ile WebSocket iletişimi,
•	Şifreli veri saklama ve çözme,
•	Frontend–backend entegrasyonu
başarıyla gerçekleştirilmiştir.


DERS YÜRÜTÜCÜSÜ:
•	ARŞ. GÖR.HAKAN AYDIN

