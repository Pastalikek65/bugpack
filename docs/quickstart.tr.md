# Türkçe hızlı başlangıç

BugPack HAR dosyası, UTF-8 log ve PNG/JPEG ekran görüntülerini bilgisayarınızda inceler, temiz kopyalarını ve hata raporunu ZIP olarak dışa aktarır. Hesap, ücretli API veya dosya yükleme sunucusu gerekmez. MVP henüz yayımlanmamıştır; doğrulama tamamlanmadan kararlı sürüm olarak sunulmaz.

Node.js 24 ve güncel Chromium tabanlı tarayıcıyla:

```sh
npm ci
npm run build
node scripts/serve.mjs --root dist --port 4174
```

`http://127.0.0.1:4174` adresini açın. `examples/sample.har`, `sample.log`, `sample.png` seçin. Kaynak ve temiz metni yan yana inceleyin; örnek logdaki e-postayı temiz kopyadan elle kaldırın. Görüntüdeki tokenı opak siyah alanla kapatın; **Apply masks and regenerate PNG** ile temiz görüntüyü üretin. Hata başlığı, tekrar üretim adımları, beklenen/gerçek sonuç ve ortam bilgilerini yazın. Her temiz dosyayı incelediğinizi işaretleyip **Build and download ZIP** seçin.

MVP HAR gövdelerini, cookie/authentication alanlarını ve desteklenmeyen ek alanları dışarıda bırakır; atlananlar işlem özetinde görünür. ZIP orijinalleri otomatik eklemez. Düzenleme, rapor veya maske değişikliği inceleme onayını sıfırlar. Otomatik temizleme her sırrı veya kişisel veriyi bulmayı garanti etmez; paylaşmadan önce metni, URL’leri, pikselleri ve raporu inceleyin.

Sınırlar ve platform kanıtları: [destek](support.md), [doğrulama](verification.md), [yol haritası](roadmap.md).
