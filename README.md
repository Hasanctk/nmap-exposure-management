# Nmap Scanning & Threat Intelligence Service API

FastAPI, Celery, Redis ve Docker Compose tabanlı; asenkron görev kuyruğuyla çalışan, iki aşamalı ağ keşfi, paket kaybı koruması, optimize agresif analiz, hibrit CVE eşleştirmesi ve tarama fark analizi (diff) yapan kurumsal ağ güvenliği mikroservisi.

---

## 1. Amaç ve Kapsam

Geleneksel Nmap taramalarını daha kontrollü, hızlı ve güvenilir hâle getiren bir ağ keşif servisi sunulmuştur. Sistem basit bir komut satırı sarmalayıcısı (wrapper) değildir; hedef sayısı, port kapsamı ve seçilen profile göre önce hızlı keşif, ardından yalnızca açık portlarda ayrıntılı analiz yürüten iki aşamalı akıllı bir strateji uygular.

---

## 2. Mimari ve Bileşenler

Sistem, kaynak tüketimini optimize etmek ve komut enjeksiyonu açıklarını engellemek amacıyla katmanlı mikroservis yapısında kurgulanmıştır:

* **Web Gateway (`FastAPI / Uvicorn`):** İstekleri karşılar, Pydantic şemalarıyla IP/CIDR girdilerini doğrular, işleri asenkron olarak başlatır (`202 Accepted`) ve Swagger/ReDoc dökümantasyonunu sunar.
* **Mesaj Kuyruğu & Önbellek (`Redis`):** Celery görev kuyruğunu (broker/backend) yönetir ve mükerrer istekleri engellemek için 3600 saniyelik (1 saat) TTL önbellekleme sağlar.
* **İşçi Motoru (`Celery Worker`):** İşletim sistemi seviyesinde `nmap` ikili dosyasını çalıştırır; ham soketler (`cap_add: NET_RAW, NET_ADMIN`) ve genişletilmiş dosya tanıtıcıları (`ulimits: nofile: 65535`) üzerinden paket düzeyinde analiz ve işletim sistemi parmak izi tespiti yapar.

---

## 3. Temel Teknik Özellikler ve Performans Optimizasyonları

### Çok Aşamalı Akıllı Tarama (Multi-Stage Discovery)
Büyük ağ bloklarında tüm portları doğrudan derin servis bayraklarıyla taramanın getirdiği kaynak israfını ve gecikmeyi önlemek için süreç iki aşamaya ayrılmıştır:
1. **Keşif Aşaması (Discovery):** `-sS -T4 --open -n` gibi profillere özel bayraklarla ağ taranır; yalnızca yanıt veren canlı IP adresleri ve açık portlar süzülür.
2. **Servis Aşaması (Service):** Yanıt vermeyen kapalı adresler elenir. Yalnızca 1. aşamada canlı çıkan IP ve açık port listesine yönelik sürüm (`-sV`) ve işletim sistemi (`-O`) analizi koşturulur.

### Dağıtık CIDR Parçalama (Map-Reduce Chunking)
`/16` gibi devasa bloklarda (65.536 IP) tek bir Nmap sürecinin kilitlenmesini önlemek için:
* Ağ otomatik olarak `/24` alt bloklarına bölünür (`split_cidr_target`).
* Celery `group` yapısıyla alt parçalar eşzamanlı worker kanallarına dağıtılır (`--concurrency=8`) ve sonuçlar ana görevde birleştirilir.

### Paket Kaybı Koruması ve RTT Zamanlama
Yoğun taramalarda paket düşmesi sonucu oluşabilecek yalancı negatifleri (False Negative) önlemek için:
* Katı paket basımı yerine dinamik gidiş-dönüş süresi limitleri (`--initial-rtt-timeout 200ms`, `--max-rtt-timeout 800-1500ms`) kullanılır.
* Cevapsız paketler için otomatik yeniden deneme (`--max-retries 2/3`) devreye girer.
* Parser katmanında şüpheli (`filtered` / `open|filtered`) durumlar filtrelenerek 2. aşamada TCP el sıkışmasıyla çapraz doğrulama yapılır.

### Raw SYN Stealth Scan (Netcat / Kernel FD Darboğazı Çözümü)
Tam 3-Way Handshake (`connect()`) yapan ve dosya tanıtıcılarını (FD) hızla tüketen Netcat tarzı yapılar yerine:
* Doğrudan işletim sistemi çekirdeğini atlayan **SYN Stealth (`-sS`)** paketleri üretilir.
* Host keşfinde gereksiz beklemeleri önlemek için akıllı SYN probing (`-PS80,443,22`) uygulanır.

### Optimize Edilmiş Agresif Analiz (`-A` Alternatifi)
Standart `nmap -A` komutunun yarattığı donmaları engellemek için:
* Gereksiz paket üreten `--traceroute` kaldırılmıştır.
* Lua scriptlerinin sonsuz döngüye girmemesi için zaman aşımı emniyeti (`--script-timeout 10s`) getirilmiştir.
* Ağır sürüm tespiti dengelenmiş (`--version-intensity 5`) ve OS deneme sayısı sınırlandırılmıştır (`--max-os-tries 1`).

### Hibrit Zafiyet Korelasyonu (CVE & CVSS Engine)
Servis taramasında tespit edilen ürün ve sürüm bilgileri (Dropbear, Dnsmasq, Samba vb.):
1. **Redis Cache (L1):** Daha önce sorgulandıysa sonuç doğrudan bellekten (<1 ms) getirilir (TTL: 24 Saat).
2. **Canlı API (L2):** Yeni tespit edilen servisler CIRCL/cve-search açık API'si üzerinden dinamik sorgulanır.
3. **Statik Fallback (L3):** Ağ bağlantısı kesildiğinde veya API yanıt vermediğinde yerel CVE veritabanı devreye girer.

### Ağ Değişiklik ve Fark Analizi (Scan Diff Engine)
`GET /scan/{current_id}/diff/{previous_id}` rotası üzerinden iki bağımsız tarama kıyaslanır; ağda sonradan açılan yeni portlar (+), kapanan portlar (-) ve değişen servis versiyonları delta verisi olarak sunulur.

---

## 4. Kod Tabanı Modül Haritası

```text
nmap_service/
├── docker-compose.yml          # Servislerin (web, worker, redis) orkestrasyonu ve ulimits
├── Dockerfile                  # Python 3.11 + Nmap çalışma ortamı
├── requirements.txt            # Bağımlılıklar (FastAPI, Celery, Redis, defusedxml, httpx vb.)
└── app/
    ├── main.py                 # FastAPI rotaları ve yaşam döngüsü
    ├── schemas.py              # Pydantic modelleri ve IP/CIDR validatorları
    ├── scanner.py              # Nmap argümanları, profiller ve optimize -A haritalaması
    ├── parser.py               # defusedxml ile XML -> JSON dönüştürücü ve durum filtreleme
    ├── celery_worker.py        # Asenkron görevler, CIDR chunking ve timeout kurtarma
    ├── vuln_matcher.py         # Canlı API + Redis önbellekli hibrit CVE motoru
    ├── diff_engine.py          # İki tarama arasındaki delta/fark analizi
    ├── reporter.py             # Markdown, HTML ve Diff HTML şablon üreticileri
    └── tests/
        └── test_api.py         # Pytest API entegrasyon testleri

## 5 . Kurulum ve Çalıştırma Rehberi

docker compose up -d --build

Servis hazır olduğunda etkileşimli dokümantasyon sayfalarına erişilebilir:

Swagger UI: http://localhost:8000/docs

ReDoc UI: http://localhost:8000/redoc

Testleri Yürütme
API doğrulama testlerini, girdi denetimi kurallarını ve görev başlatma mekanizmalarını konteyner içinde çalıştırmak için:

docker compose exec -e PYTHONPATH=. web pytest app/tests/test_api.py
Örnek İp'ler: 
    192.168.1.0/24
    10.0.0.0/24
    127.0.0.1/32
