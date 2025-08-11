#include <WiFi.h>
#include <WebServer.h>
#include <mbedtls/aes.h>
#include <mbedtls/base64.h>

const char* ssid = "CryptoAP";
const char* password = "12345678";

WebServer server(80);

#define AES_KEY_SIZE 16  // 128-bit AES
#define AES_BLOCK_SIZE 16

// IV ثابت (برای نمونه) - در عمل بهتر است IV تصادفی و در ابتدای پیام ارسال شود
const uint8_t iv[AES_BLOCK_SIZE] = {
  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
  0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};

// -- HTML صفحه (همان UI قبلی با تغییرات جزیی برای انتخاب الگوریتم و ورودی کلید)
const char index_html[] PROGMEM = R"rawliteral(
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Crypto Station — AES & Base64</title>
<style>
  :root{
    --bg:#041017;
    --card:#112233dd;
    --accent:#00e6ff;
    --muted:#9fb0c8;
    --shadow:0 10px 30px rgba(0,230,255,0.2);
  }
  html,body{
    height:100%;
    margin:0;
    font-family:Inter,system-ui,Segoe UI,Roboto,Arial;
    background:
      linear-gradient(180deg,#01060a,#06202a),
      url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100" fill="%2300e6ff" opacity="0.05"><circle cx="50" cy="50" r="40"/></svg>') repeat;
    color:#e8fbff;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
  }
  header{
    padding:18px;
    border-bottom:1px solid rgba(255,255,255,0.06);
    display:flex;
    gap:12px;
    align-items:center;
    background:rgba(0,0,0,0.3);
    box-shadow: var(--shadow);
  }
  .brand{
    font-size:20px;
    font-weight:800;
    letter-spacing:1.2px;
    user-select:none;
  }
  .wrap{
    max-width:1180px;
    margin:20px auto;
    padding:18px;
    display:grid;
    gap:18px;
  }
  .grid2{
    display:grid;
    grid-template-columns:1fr 1fr;
    gap:18px;
  }
  .card{
    background: var(--card);
    border-radius:12px;
    padding:18px;
    box-shadow: var(--shadow);
    border:1px solid rgba(255,255,255,0.05);
  }
  h2{
    margin:0 0 12px 0;
    font-size:18px;
    user-select:none;
  }
  textarea{
    width:100%;
    height:360px;
    padding:14px;
    border-radius:10px;
    border:1px solid rgba(255,255,255,0.04);
    background:rgba(0,0,0,0.35);
    color:inherit;
    resize:none;
    font-size:15px;
    line-height:1.6;
    box-sizing:border-box;
    overflow-y: auto;
    font-family: monospace, monospace;
  }
  select,input,button{
    padding:10px;
    border-radius:10px;
    border:1px solid rgba(255,255,255,0.04);
    background:rgba(255,255,255,0.02);
    color:inherit;
    font-size:14px;
  }
  .row{
    display:flex;
    gap:8px;
    align-items:center;
    margin-top:10px;
  }
  .muted{
    color:var(--muted);
    font-size:13px;
    user-select:none;
  }
  .cta{
    background:linear-gradient(90deg,var(--accent),#7af);
    border:none;
    padding:10px 14px;
    border-radius:10px;
    color:#02111a;
    font-weight:800;
    cursor:pointer;
    user-select:none;
    transition: background 0.3s ease;
  }
  .cta:hover {
    background:linear-gradient(90deg,#00ffff,#33ccff);
  }
  .download{
    display:inline-block;
    margin-top:10px;
    color:var(--accent);
    font-weight:700;
    text-decoration:none;
    user-select:none;
  }
  .status{
    margin-top:8px;
    font-size:13px;
    color:#cde;
    min-height: 18px;
    user-select:none;
  }
  footer{
    padding:10px;
    text-align:center;
    color:var(--muted);
    font-size:14px;
    user-select:none;
  }
  @media (max-width:900px){
    .grid2{grid-template-columns:1fr;}
    textarea{height:260px;}
  }
</style>
</head>
<body>
<header>
  <div class="brand">Crypto Station</div>
  <div class="muted">AP Mode — 192.168.4.1</div>
</header>

<div class="wrap">
  <div class="grid2">
    <div class="card">
      <h2>Encrypt / Process — Text or File</h2>
      <div class="muted">Paste text (فارسی/English) or upload a file.</div>
      <div style="height:10px"></div>
      <textarea id="inputText" placeholder="Type or paste text here..."></textarea>

      <div class="row">
        <input type="file" id="fileInput" accept="*/*">
        <div style="flex:1"></div>
        <div class="muted">Max: 2 MB (PoC)</div>
      </div>

      <div style="height:12px"></div>
      <label class="muted">Algorithm:</label>
      <select id="algoSelectEncrypt" style="width:100%;margin-top:4px;margin-bottom:6px;">
        <option value="base64">Base64 encode (no key)</option>
        <option value="aes">AES-128-CBC encrypt (with key)</option>
      </select>

      <input id="keyField" placeholder="Enter key (16 chars for AES)" maxlength="16" style="width:100%;margin-bottom:10px;" disabled>

      <div class="row">
        <button class="cta" onclick="processData(true)">Encrypt / Encode</button>
      </div>

      <div style="height:12px"></div>
      <label class="muted">Result (preview & download):</label>
      <textarea id="resultOut" readonly placeholder="Result will appear here"></textarea>
      <div class="row">
        <a id="downloadLink" class="download"></a>
        <div id="previewBase64" class="muted" style="margin-left:12px"></div>
      </div>
      <div id="status" class="status"></div>
    </div>

    <div class="card">
      <h2>Decrypt / Verify — Text or File</h2>
      <div class="muted">Paste Base64 content or upload result file.</div>
      <div style="height:10px"></div>
      <textarea id="inputText2" placeholder="Paste Base64 content here..."></textarea>

      <div class="row">
        <input type="file" id="fileInput2" accept="*/*">
        <div style="flex:1"></div>
      </div>

      <div style="height:12px"></div>
      <label class="muted">Algorithm:</label>
      <select id="algoSelectDecrypt" style="width:100%;margin-top:4px;margin-bottom:6px;">
        <option value="base64">Base64 decode (no key)</option>
        <option value="aes">AES-128-CBC decrypt (with key)</option>
      </select>

      <input id="keyField2" placeholder="Enter key (16 chars for AES)" maxlength="16" style="width:100%;margin-bottom:10px;" disabled>

      <div class="row">
        <button class="cta" onclick="processData(false)">Decrypt / Decode</button>
      </div>

      <div style="height:12px"></div>
      <label class="muted">Result (preview & download):</label>
      <textarea id="resultOut2" readonly placeholder="Result will appear here"></textarea>
      <div class="row">
        <a id="downloadLink2" class="download"></a>
      </div>
      <div id="status2" class="status"></div>
    </div>
  </div>
</div>

<footer>Power by Amir — 2025</footer>

<script>
  // Enable/disable key input based on selected algorithm
  const algoEncrypt = document.getElementById('algoSelectEncrypt');
  const keyField = document.getElementById('keyField');
  algoEncrypt.addEventListener('change', () => {
    keyField.disabled = (algoEncrypt.value !== 'aes');
  });
  const algoDecrypt = document.getElementById('algoSelectDecrypt');
  const keyField2 = document.getElementById('keyField2');
  algoDecrypt.addEventListener('change', () => {
    keyField2.disabled = (algoDecrypt.value !== 'aes');
  });

  // Handle file inputs for encryption
  const fileInput = document.getElementById('fileInput');
  fileInput.addEventListener('change', e => {
    const file = e.target.files[0];
    if (!file) return;
    if (file.size > 2 * 1024 * 1024) {
      alert('File size exceeds 2 MB');
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      document.getElementById('inputText').value = reader.result;
    };
    reader.readAsText(file);
  });

  // Handle file inputs for decryption
  const fileInput2 = document.getElementById('fileInput2');
  fileInput2.addEventListener('change', e => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      document.getElementById('inputText2').value = reader.result;
    };
    reader.readAsText(file);
  });

  async function processData(isEncrypt) {
    const inputText = isEncrypt ? document.getElementById('inputText').value : document.getElementById('inputText2').value;
    const algo = isEncrypt ? algoEncrypt.value : algoDecrypt.value;
    const key = isEncrypt ? keyField.value : keyField2.value;
    const resultOut = isEncrypt ? document.getElementById('resultOut') : document.getElementById('resultOut2');
    const status = isEncrypt ? document.getElementById('status') : document.getElementById('status2');
    const downloadLink = isEncrypt ? document.getElementById('downloadLink') : document.getElementById('downloadLink2');

    status.textContent = '';
    downloadLink.textContent = '';
    downloadLink.href = '#';

    if (!inputText) {
      status.textContent = 'Input text is empty!';
      return;
    }
    if (algo === 'aes' && key.length !== 16) {
      status.textContent = 'Key must be exactly 16 characters for AES-128.';
      return;
    }

    status.textContent = 'Processing...';

    try {
      const response = await fetch(`/api?data=${encodeURIComponent(inputText)}&algo=${algo}&key=${encodeURIComponent(key)}&encrypt=${isEncrypt?1:0}`, {method:'GET'});
      if (!response.ok) throw new Error(`Server error ${response.status}`);

      const text = await response.text();
      if (!text) throw new Error('Empty response from server');

      resultOut.value = text;

      // Setup download link
      const filename = isEncrypt ? 'encrypted.txt' : 'decrypted.txt';
      downloadLink.href = URL.createObjectURL(new Blob([text], {type:'text/plain'}));
      downloadLink.download = filename;
      downloadLink.textContent = 'Download Result';
      status.textContent = 'Done!';
    } catch(e) {
      status.textContent = `Error: ${e.message}`;
    }
  }
</script>
</body>
</html>
)rawliteral";


// --- Helpers for AES + Base64 ---

// PKCS7 padding
void pkcs7_pad(uint8_t *data, size_t data_len, size_t block_size, uint8_t *padded, size_t *padded_len) {
  size_t pad_len = block_size - (data_len % block_size);
  memcpy(padded, data, data_len);
  for (size_t i = 0; i < pad_len; i++) {
    padded[data_len + i] = (uint8_t)pad_len;
  }
  *padded_len = data_len + pad_len;
}

// PKCS7 unpadding
bool pkcs7_unpad(uint8_t *data, size_t data_len, size_t *unpadded_len) {
  if (data_len == 0) return false;
  uint8_t pad = data[data_len - 1];
  if (pad == 0 || pad > AES_BLOCK_SIZE) return false;
  for (size_t i = 0; i < pad; i++) {
    if (data[data_len - 1 - i] != pad) return false;
  }
  *unpadded_len = data_len - pad;
  return true;
}

// AES128-CBC encrypt
bool aes_encrypt(const uint8_t *key, const uint8_t *input, size_t input_len,
                 uint8_t *output, size_t *output_len) {
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);

  // Pad input
  size_t padded_len;
  uint8_t padded[5120]; // max input 5KB, for safety
  if(input_len > 5000) return false;
  pkcs7_pad((uint8_t*)input, input_len, AES_BLOCK_SIZE, padded, &padded_len);

  if (mbedtls_aes_setkey_enc(&aes, key, AES_KEY_SIZE * 8) != 0) {
    mbedtls_aes_free(&aes);
    return false;
  }

  uint8_t iv_copy[AES_BLOCK_SIZE];
  memcpy(iv_copy, iv, AES_BLOCK_SIZE);

  if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len, iv_copy, padded, output) != 0) {
    mbedtls_aes_free(&aes);
    return false;
  }
  mbedtls_aes_free(&aes);
  *output_len = padded_len;
  return true;
}

// AES128-CBC decrypt
bool aes_decrypt(const uint8_t *key, const uint8_t *input, size_t input_len,
                 uint8_t *output, size_t *output_len) {
  if (input_len % AES_BLOCK_SIZE != 0) return false;
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);

  if (mbedtls_aes_setkey_dec(&aes, key, AES_KEY_SIZE * 8) != 0) {
    mbedtls_aes_free(&aes);
    return false;
  }

  uint8_t iv_copy[AES_BLOCK_SIZE];
  memcpy(iv_copy, iv, AES_BLOCK_SIZE);

  if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, input_len, iv_copy, input, output) != 0) {
    mbedtls_aes_free(&aes);
    return false;
  }

  // Unpad
  size_t unpadded_len;
  if (!pkcs7_unpad(output, input_len, &unpadded_len)) {
    mbedtls_aes_free(&aes);
    return false;
  }
  mbedtls_aes_free(&aes);
  *output_len = unpadded_len;
  return true;
}

// Base64 encode
String base64_encode(const uint8_t *data, size_t len) {
  size_t output_len = 0;
  mbedtls_base64_encode(NULL, 0, &output_len, data, len);
  uint8_t *out_buf = (uint8_t*)malloc(output_len + 1);
  if (!out_buf) return String();
  if (mbedtls_base64_encode(out_buf, output_len, &output_len, data, len) != 0) {
    free(out_buf);
    return String();
  }
  out_buf[output_len] = 0;
  String s = String((char*)out_buf);
  free(out_buf);
  return s;
}

// Base64 decode
bool base64_decode(const char *input, uint8_t *output, size_t *output_len) {
  size_t out_len = 0;
  if (mbedtls_base64_decode(NULL, 0, &out_len, (const uint8_t*)input, strlen(input)) != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
    return false;
  }
  if (*output_len < out_len) return false;
  if (mbedtls_base64_decode(output, *output_len, &out_len, (const uint8_t*)input, strlen(input)) != 0) {
    return false;
  }
  *output_len = out_len;
  return true;
}

void handleRoot() {
  server.send_P(200, "text/html", index_html);
}

// API handler
void handleAPI() {
  String data = server.arg("data");
  String algo = server.arg("algo");
  String key = server.arg("key");
  int encryptFlag = server.arg("encrypt").toInt();

  if (algo != "base64" && algo != "aes") {
    server.send(400, "text/plain", "Invalid algorithm");
    return;
  }

  if (algo == "aes" && key.length() != 16) {
    server.send(400, "text/plain", "Key must be 16 characters");
    return;
  }

  if (data.length() == 0) {
    server.send(400, "text/plain", "Data is empty");
    return;
  }

  if (algo == "base64") {
    if (encryptFlag == 1) {
      // Base64 encode
      String encoded = base64_encode((const uint8_t*)data.c_str(), data.length());
      if (encoded.length() == 0) {
        server.send(500, "text/plain", "Base64 encode failed");
        return;
      }
      server.send(200, "text/plain", encoded);
    } else {
      // Base64 decode
      size_t buf_len = 4096;
      uint8_t *buf = (uint8_t*)malloc(buf_len);
      if (!buf) {
        server.send(500, "text/plain", "Memory error");
        return;
      }
      if (!base64_decode(data.c_str(), buf, &buf_len)) {
        free(buf);
        server.send(400, "text/plain", "Base64 decode failed");
        return;
      }
      String decoded = String((char*)buf).substring(0, buf_len);
      free(buf);
      server.send(200, "text/plain", decoded);
    }
  } else if (algo == "aes") {
    uint8_t aes_key[AES_KEY_SIZE];
    memcpy(aes_key, key.c_str(), AES_KEY_SIZE);

    if (encryptFlag == 1) {
      // Encrypt with AES
      size_t out_len = 5120;
      uint8_t *out_buf = (uint8_t*)malloc(out_len);
      if (!out_buf) {
        server.send(500, "text/plain", "Memory error");
        return;
      }
      if (!aes_encrypt(aes_key, (const uint8_t*)data.c_str(), data.length(), out_buf, &out_len)) {
        free(out_buf);
        server.send(500, "text/plain", "AES encrypt failed");
        return;
      }
      // Base64 encode output
      String encoded = base64_encode(out_buf, out_len);
      free(out_buf);
      if (encoded.length() == 0) {
        server.send(500, "text/plain", "Base64 encode failed");
        return;
      }
      server.send(200, "text/plain", encoded);

    } else {
      // Decrypt with AES
      size_t b64_dec_len = 5120;
      uint8_t *b64_dec_buf = (uint8_t*)malloc(b64_dec_len);
      if (!b64_dec_buf) {
        server.send(500, "text/plain", "Memory error");
        return;
      }
      if (!base64_decode(data.c_str(), b64_dec_buf, &b64_dec_len)) {
        free(b64_dec_buf);
        server.send(400, "text/plain", "Base64 decode failed");
        return;
      }
      size_t dec_len = 5120;
      uint8_t *dec_buf = (uint8_t*)malloc(dec_len);
      if (!dec_buf) {
        free(b64_dec_buf);
        server.send(500, "text/plain", "Memory error");
        return;
      }
      if (!aes_decrypt(aes_key, b64_dec_buf, b64_dec_len, dec_buf, &dec_len)) {
        free(b64_dec_buf);
        free(dec_buf);
        server.send(400, "text/plain", "AES decrypt failed (bad key or corrupted data)");
        return;
      }
      String decoded = String((char*)dec_buf).substring(0, dec_len);
      free(b64_dec_buf);
      free(dec_buf);
      server.send(200, "text/plain", decoded);
    }
  }
}

void setup() {
  Serial.begin(115200);
  WiFi.softAP(ssid, password);
  Serial.print("AP IP: ");
  Serial.println(WiFi.softAPIP());

  server.on("/", handleRoot);
  server.on("/api", handleAPI);
  server.begin();
}

void loop() {
  server.handleClient();
}
