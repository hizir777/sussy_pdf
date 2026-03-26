**Vize Projesi Yol Haritası**:

* 1. adım: Uptime Kuma analizi
* 2. adım: Vize projesi (Şüpheli PDF Analizi)

---

## 🛠️ Proje öngereksinimi : Uptime Kuma Analiz Yol Haritası

### Adım 1: Kurulum ve `install.sh` Analizi (Reverse Engineering)
Uptime Kuma genellikle `npm` veya `docker` üzerinden kurulur, ancak topluluk tarafından sağlanan veya manuel kurulum betikleri (`extra` klasörü altındakiler gibi) kritik önem taşır.
* **Görev:** Repodaki kurulum süreçlerini (özellikle Dockerfile ve paket yönetim dosyalarını) incele.
* **Odak Noktası:** `package.json` içindeki bağımlılıklar ve kurulum sırasında dışarıdan çekilen scriptler.
* **Kritik Soru:** Dış kaynaklar (CDN'ler, API'ler) çekilirken bütünlük kontrolü (SRI hash) yapılıyor mu? Kurulum sırasında sudo yetkisi gereksiz yere isteniyor mu?

### Adım 2: İzolasyon ve İz Bırakmadan Temizlik (Forensics)
* **Görev:** Uygulamayı bir VM (Virtual Machine) içinde ayağa kaldır ve çalışırken oluşturduğu dosyaları (SQLite veritabanı, loglar, `data` klasörü) haritalandır.
* **Yöntem:** Kurulum öncesi ve sonrası sistemin bir "snapshot"ını al. `lsof -i :3001` komutuyla hangi portun dinlendiğini ve hangi process'in (PID) aktif olduğunu dökümle.
* **İspat:** Uygulamayı sildikten sonra `/app/data` veya `/var/lib/docker` altında kalıntı kalıp kalmadığını kontrol eden bir "Cleanup Verification Script" hazırla.

### Adım 3: İş Akışları ve CI/CD Pipeline Analizi
Uptime Kuma'nın `.github/workflows` dizini oldukça kalabalıktır (frontend build, docker push vb.).
* **Görev:** `frontend-build.yml` veya `docker.yml` dosyasını seç.
* **Analiz:** Kod her push edildiğinde hangi testlerden geçiyor? Docker imajları hangi mimariler (arm64, amd64) için otomatik basılıyor?
* **Webhook Kavramı:** GitHub'ın bir olay (push/merge) olduğunda senin sunucuna veya bir servise "Hey, bir değişiklik oldu, hadi aksiyona geç!" diye fısıldamasıdır.

### Adım 4: Docker Mimarisi ve Konteyner Güvenliği
Uptime Kuma'nın kalbi Docker üzerinde atar.
* **Görev:** `Dockerfile`'ı satır satır oku. Base imaj olarak ne kullanılmış? (Örn: `node:alpine` mi yoksa daha ağır bir imaj mı?)
* **Güvenlik Katmanı:** Konteyner "root" yetkisiyle mi çalışıyor yoksa sınırlı bir kullanıcı (`node` kullanıcısı gibi) mı atanmış?
* **Karşılaştırma:** VM'ler tüm işletim sistemini sanallaştırırken, Docker'ın sadece uygulama katmanını izole ettiğini ve çekirdeği (kernel) paylaştığını vurgula.

### Adım 5: Kaynak Kod ve Tehdit Modelleme (Threat Modeling)
* **Entrypoint Tespiti:** Uygulamanın giriş noktası olan `server/server.js` (veya `src/` altındaki ana dosya) dosyasını bul.
* **Auth Mekanizması:** Uptime Kuma login ekranında şifreleri nasıl saklıyor? (Bcrypt/Argon2?). Socket.io bağlantılarında yetkilendirme nasıl yapılıyor?
* **Saldırı Senaryosu:** Bir saldırgan "Status Page" üzerinden SSRF (Server Side Request Forgery) saldırısı yapabilir mi? İzleme aracı olduğu için sunucunun iç ağını taramak için kullanılabilir mi?

---

### 📊 Rapor Taslağın (Template)

| Bölüm | İçerik | Teslim Edilecek Belge |
| :--- | :--- | :--- |
| **Giriş** | Proje amacı ve seçilen repo nedenleri. | Giriş metni |
| **Kurulum Analizi** | Script incelemesi ve güvenlik açıkları. | `install_analysis.md` |
| **Adli Analiz** | Kalıntı kontrolü ve silme kanıtları. | Log çıktıları ve Ekran Görüntüleri |
| **DevOps Analizi** | CI/CD akışı ve Webhook detayları. | Akış şeması (Mermaid.js vb.) |
| **Güvenlik Mimarisi** | Docker katmanları ve Rootless kontrolü. | Güvenlik Skor Tablosu |
| **Tehdit Modeli** | Entrypoint ve Auth zaafiyet analizi. | Saldırı Senaryosu Raporu |

---

# Vize Projesi

## 📄 Şüpheli PDF Analiz Yol Haritası

Bu projenin ana amacı, görsel olarak masum görünen bir dosyanın (CV), arka planda nasıl bir "taşıyıcı" (dropper) olarak kullanılabileceğini kanıtlamaktır.

### Adım 1: İzole Analiz Laboratuvarı (Sanallaştırma)
Zararlı bir dosya ile uğraşırken ilk kural: **Asla kendi ana makineni kullanma.**
* **Görev:** Kali Linux veya benzeri bir güvenlik dağıtımı yüklü bir VM (Sanal Makine) hazırla.
* **Ağ Ayarı:** VM'in internet erişimini kes (Host-only veya No Network). Eğer exploit bir "reverse shell" deneyecekse, senin makinene zarar vermesini önlemiş olursun.

### Adım 2: PDF Anatomisi ve İlk Bakış
PDF'ler sadece metin değildir; nesnelerden (Objects) ve bu nesneler arasındaki bağlantılardan oluşur.
* **Görev:** `peepdf` aracını interaktif modda başlat: `peepdf -i supheli_cv.pdf`.
* **Analiz:** Dosya sürümü, nesne sayısı ve kaç tane "stream" (veri akışı) olduğunu incele.
* **İpucu:** `info` komutu ile dosyanın genel bir özetini çıkar.

### Adım 3: Şüpheli Etiketlerin (Flags) Peşine Düşmek
Hocanın bahsettiği `/JS`, `/JavaScript`, `/Launch` veya `/OpenAction` gibi anahtar kelimeler "tetikleyici" unsurlardır.
* **Görev:** `peepdf` çıktısında "Suspicious elements" kısmına odaklan.
* **Kritik Sorgu:** * **`/OpenAction`:** Dosya açılır açılmaz bir şeylerin tetiklendiğini gösterir.
    * **`/JS` veya `/JavaScript`:** İçeride bir kod çalıştığını gösterir.
    * **`/Launch`:** Dışarıdan bir programın (örneğin `cmd.exe`) çalıştırılmaya çalışıldığını gösterir.

### Adım 4: Gizli Nesnelerin ve Stream'lerin Çıkarılması
Saldırganlar genellikle kodu `/FlateDecode` gibi yöntemlerle sıkıştırarak veya gizleyerek (obfuscation) `strings` gibi basit araçlardan kaçırırlar.
* **Görev:** Şüpheli nesneyi seç (Örn: `object 5`).
* **Analiz:** Nesnenin içeriğini oku. Eğer içerik okunamaz haldeyse (binary/encoded), `peepdf` üzerinden bu akışı (`stream`) bir dosyaya çıkar veya decode et.
* **Komut:** `object <id>` ve sonrasında `raw` veya `js_analyser`.

### Adım 5: Kod Analizi ve "Niyet" Tespiti (Reverse Engineering)
Artık elinde PDF'in içinden söküp aldığın çıplak kod (genellikle JavaScript) var.
* **Görev:** Bu kod ne yapmaya çalışıyor? Bir URL'den dosya mı indiriyor? Kullanıcının bilgisayarında bir kayıt defteri (registry) anahtarı mı değiştiriyor?
* **Raporlama:** Kodun tehlikeli kısmını (payload) ekran görüntüleriyle belgele.

---

### 📝 Proje Raporunda Yer Alması Gereken Bölümler

| Bölüm | Açıklama |
| :--- | :--- |
| **Dosya Özeti** | Dosyanın ismi, MD5/SHA256 hash değerleri. |
| **Statik Analiz** | `peepdf` ile bulunan şüpheli etiketlerin listesi. |
| **Nesne İncelemesi** | Hangi nesnenin (object) zararlı içerik taşıdığının ispatı. |
| **Kod Çözme (Decoding)** | Gizlenmiş (obfuscated) kodun nasıl görünür hale getirildiği. |
| **Sonuç ve Korunma** | Bu exploit'in etkisi nedir? Modern PDF okuyucular buna karşı nasıl önlemler alıyor? |

---