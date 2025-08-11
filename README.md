
──────────────────────────────────────────────────────────────────────────────
        ✦ CRYPTO STATION ✦ — AES-128-CBC + Base64 Web Tool on ESP32
──────────────────────────────────────────────────────────────────────────────

> 🛡 "Encrypt like a ghost, decrypt like a shadow — no one sees you coming."  

-------------------------------------------------------------------------------
## 🧩 OVERVIEW
Crypto Station is a **self-contained encryption server** running directly on an **ESP32**.  
It uses **AES-128-CBC** for symmetric encryption and **Base64** for encoding binary data into safe ASCII text, all processed locally on the device — completely **offline**.

Once powered, the ESP32:
1. Boots in **Access Point mode** (AP)
2. Hosts a **local web interface**
3. Accepts **plaintext or file input**
4. Processes data through the **crypto engine**
5. Returns the encrypted/decrypted result instantly

No cloud, no internet, no logs — pure edge security.

-------------------------------------------------------------------------------
## ⚙ SYSTEM ARCHITECTURE

[BOOT] → [AP MODE: SSID=CryptoAP, PASS=12345678]
    ↓
[WEB SERVER: HTML/CSS/JS UI]
    ↓
[INPUT LAYER]
    |— Text Mode (textarea)
    |— File Mode (upload)
    |— Key Input (16-byte for AES-128)
    ↓
[CRYPTO CORE]
    |— AES-128-CBC (mbedtls_aes_setkey_enc/dec)
    |— PKCS7 Padding
    |— Base64 Encode/Decode (mbedtls_base64_encode/decode)
    ↓
[OUTPUT LAYER]
    |— Download encrypted file
    |— Copy encrypted text

-------------------------------------------------------------------------------
## 🛠 IMPLEMENTATION DETAILS

### 1. **Network Layer**
- **ESP32 AP Mode**  
  ```cpp
  WiFi.softAP("CryptoAP", "12345678");
  server.begin();
  ```
- Creates isolated Wi-Fi network for secure, offline access.

### 2. **Web Interface**
- Served from SPIFFS
- HTML5 + CSS3 + Vanilla JS for smooth UI
- AJAX requests to `/encrypt` and `/decrypt` endpoints

### 3. **Crypto Engine**
- **AES-128-CBC**
  ```cpp
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, key, 128);
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, length, iv, input, output);
  ```
- **Base64** for text-safe output
- Uses PKCS7 padding to align data to AES block size

### 4. **Security Considerations**
- Static IV (demo) → Replace with random IV for production
- All processing done in RAM → no disk writes
- Max file size ~2MB (due to ESP32 memory limits)

-------------------------------------------------------------------------------
## 🚀 INSTALLATION & USAGE

**1. Clone Repository**
```bash
git clone https://github.com/Amir-Mahdi-Barati/Crypto-Station
```

**2. Setup Arduino IDE**
- Install **ESP32 Core**
- Select `ESP32 Dev Module`

**3. Upload Code**
- Connect board
- Choose COM port
- Flash firmware

**4. Connect to Device**
- SSID: `CryptoAP`
- PASS: `12345678`
- Open browser → `http://192.168.4.1`

**5. Encrypt / Decrypt**
- Choose Text or File mode
- Enter Key
- Click **Encrypt** or **Decrypt**
- Download or copy result

-------------------------------------------------------------------------------
## 📡 REAL-WORLD USE CASES
- **Field Ops Encryption** — Secure comms without internet
- **Data-in-Transit Protection** — Before transferring via USB
- **Air-Gapped Crypto Lab** — Research & training
- **IoT Secure Gateway** — Lightweight device-level encryption

-------------------------------------------------------------------------------
## ⚠ LIMITATIONS
- Static IV — not secure for multiple messages with same key
- RAM limited — large files not supported
- AP mode only — no STA (client) mode in current version

-------------------------------------------------------------------------------
## 📜 LICENSE
MIT License — Free to use, modify, and distribute.

-------------------------------------------------------------------------------
## POWER BY
GitHub: https://github.com/Amir-Mahdi-Barati
──────────────────────────────────────────────────────────────────────────────
