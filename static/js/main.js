console.log(">>> main.js yüklendi");

// Socket bağlantısı
const socket = io();
console.log(">>> socket objesi oluşturuldu:", socket);

// ------------------------------
// DOM yardımcıları
// ------------------------------
const $ = (id) => document.getElementById(id);

const messagesList   = $("messages");
const messageInput   = $("messageInput");
const sendBtn        = $("sendBtn");

const usernameInput  = $("usernameInput");
const roomInput      = $("roomInput");
const joinBtn        = $("joinBtn");

const algoSelect     = $("algoSelect");
const keyInput       = $("keyInput");
const keyHint        = $("keyHint");

// Header: odadaki kullanıcılar chip'i (B)
const roomUsersChip  = $("roomUsersChip");
const roomUsersText  = $("roomUsersText");

// Hill (encrypt)
const hillOptions    = $("hillOptions");
const hillSizeInput  = $("hillSize");

// Decrypt alanları
const decAlgoSelect  = $("decAlgoSelect");
const cipherInput    = $("cipherInput");
const decKeyInput    = $("decKeyInput");
const decKeyHint     = $("decKeyHint");
const decryptBtn     = $("decryptBtn");
const decryptResult  = $("decryptResult");

// Hill (decrypt) - index.html'e ekledik
const decHillOptions   = $("decHillOptions");
const decHillSizeInput = $("decHillSize");

// basit state
let currentRoom = "";

// ------------------------------
// Wire / DB format yardımcıları
// ------------------------------

// server wire format: { encoding: "b64"|"str", data: "..." }
// DB format: "b64:<...>" or "str:<...>"
// UI input format: plain string OR wire object OR "b64:..." / "str:..."

function isWireObj(x) {
  return x && typeof x === "object" && typeof x.encoding === "string" && typeof x.data === "string";
}

function parseDbPrefix(s) {
  if (typeof s !== "string") return null;
  if (s.startsWith("b64:")) return { encoding: "b64", data: s.slice(4) };
  if (s.startsWith("str:")) return { encoding: "str", data: s.slice(4) };
  return null;
}

function normalizeCiphertextToWire(input) {
  if (isWireObj(input)) return input;

  if (typeof input === "string") {
    const trimmed = input.trim();
    const parsed = parseDbPrefix(trimmed);
    if (parsed) return parsed;

    // default: str (kullanıcı plaintext/base64 farkını bilmeyebilir)
    return { encoding: "str", data: trimmed };
  }

  return { encoding: "str", data: String(input ?? "") };
}

function wireToDisplayString(wire) {
  if (isWireObj(wire)) return wire.data;

  if (typeof wire === "string") {
    const parsed = parseDbPrefix(wire);
    return parsed ? parsed.data : wire;
  }

  return String(wire ?? "");
}

function safeText(s) {
  return (s ?? "").toString();
}

// Basit XSS kaçınma
function escapeHtml(str) {
  return safeText(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

// ------------------------------
// Mesaj render
// ------------------------------
function appendMessage({ username, algo, wire, created_at, isHistory }) {
  if (!messagesList) return;

  const u = safeText(username || "unknown");
  const a = safeText(algo || "-");
  const t = created_at ? safeText(created_at) : "";
  const c = wireToDisplayString(wire);

  const li = document.createElement("li");
  li.className = "msg";

  // ciphertext satırında wire objeyi sakla (decrypt'e kolay kopyalama için)
  const wireObj = normalizeCiphertextToWire(wire);
  li.dataset.wire = JSON.stringify(wireObj);

  li.innerHTML = `
    <div class="meta">
      <b>${escapeHtml(u)}</b>
      <span class="muted">${escapeHtml(a)}${t ? " • " + escapeHtml(t) : ""}${isHistory ? " • history" : ""}</span>
    </div>
    <div class="cipher">
      <span class="label">ciphertext:</span>
      <code class="ct">${escapeHtml(c)}</code>
      <button class="copyBtn" type="button">Kopyala</button>
      <button class="useDecryptBtn" type="button">Decrypt’e koy</button>
    </div>
  `;

  messagesList.appendChild(li);
  messagesList.scrollTop = messagesList.scrollHeight;

  const copyBtn = li.querySelector(".copyBtn");
  const useBtn  = li.querySelector(".useDecryptBtn");

  if (copyBtn) {
    copyBtn.addEventListener("click", async () => {
      const toCopy = JSON.stringify(wireObj);
      try {
        await navigator.clipboard.writeText(toCopy);
        copyBtn.textContent = "Kopyalandı";
        setTimeout(() => (copyBtn.textContent = "Kopyala"), 900);
      } catch (e) {
        console.warn("clipboard fail", e);
        alert("Kopyalanamadı. Tarayıcı izinlerini kontrol et.");
      }
    });
  }

  if (useBtn) {
    useBtn.addEventListener("click", () => {
      if (cipherInput) cipherInput.value = JSON.stringify(wireObj);
      if (decryptResult) {
        decryptResult.classList.remove("error");
        decryptResult.textContent = "";
      }
      if (cipherInput) cipherInput.focus();
    });
  }
}

// System / join-leave gibi mesajlar için ayrı render
function appendSystemMessage(text, created_at = "") {
  if (!messagesList) return;

  const li = document.createElement("li");
  li.className = "msg system";

  li.innerHTML = `
    <div class="meta">
      <b>System</b>
      <span class="muted">${created_at ? escapeHtml(created_at) : ""}</span>
    </div>
    <div class="cipher">
      <span class="label">event:</span>
      <code class="ct">${escapeHtml(text)}</code>
    </div>
  `;

  messagesList.appendChild(li);
  messagesList.scrollTop = messagesList.scrollHeight;
}

// ------------------------------
// Header chip: room users
// ------------------------------
function setRoomUsers(users) {
  if (!roomUsersChip || !roomUsersText) return;

  if (!Array.isArray(users) || users.length === 0) {
    roomUsersText.textContent = "";
    roomUsersChip.style.display = "none";
    return;
  }

  roomUsersText.textContent = users.join(", ");
  roomUsersChip.style.display = "";
}

function resetRoomUsersChip() {
  setRoomUsers([]);
}

// ------------------------------
// Algo -> key hint + Hill toggle
// ------------------------------
function setKeyHints(algo) {
  const a = (algo || "").toUpperCase();

  let hintEnc = "Anahtar gir (algoritmaya göre format değişir).";
  let hintDec = "Çözme anahtarı gir (algoritmaya göre format değişir).";

  if (a === "AES") {
    hintEnc = "AES: 16/24/32 byte anahtar (projedeki implementasyona göre).";
    hintDec = hintEnc;
  } else if (a === "DES") {
    hintEnc = "DES: 8 byte anahtar.";
    hintDec = hintEnc;
  } else if (a === "3DES" || a === "TRIPLEDES") {
    hintEnc = "3DES: 16 veya 24 byte anahtar.";
    hintDec = hintEnc;
  } else if (a === "BLOWFISH") {
    hintEnc = "Blowfish: değişken uzunluk (genelde 4–56 byte).";
    hintDec = hintEnc;
  } else if (a === "RC2") {
    hintEnc = "RC2: değişken uzunluk anahtar (uygulamana bağlı).";
    hintDec = hintEnc;
  } else if (a === "RC5") {
    hintEnc = "RC5: değişken uzunluk anahtar (uygulamana bağlı).";
    hintDec = hintEnc;
  } else if (a === "MANUAL_AES" || a === "MANUALAES" || a === "MANUAL AES") {
    hintEnc = "Manual AES: (demo) anahtar formatını backend kurallarına göre gir.";
    hintDec = hintEnc;
  } else if (a === "CAESAR") {
    hintEnc = "Caesar: kaydırma sayısı (örn: 3).";
    hintDec = hintEnc;
  } else if (a === "AFFINE") {
    hintEnc = "Affine: a,b (örn: 5,8). a ile 26 aralarında asal olmalı.";
    hintDec = hintEnc;
  } else if (a === "VIGENERE") {
    hintEnc = "Vigenere: metin anahtar (örn: LEMON).";
    hintDec = hintEnc;
  } else if (a === "HILL") {
    hintEnc = "Hill: anahtar matrisi + boyut. Key formatı backend implementasyonuna bağlı.";
    hintDec = hintEnc;
  } else if (a === "RSA") {
    hintEnc = "RSA: UI public key’i /api/public-key’den alır. (Session key akışı varsa backend yönetir.)";
    hintDec = "RSA: decrypt için private key gerekir (demo akışın backend’e bağlı).";
  } else if (a === "DSA") {
    hintEnc = "DSA: şifreleme değil imza. Ciphertext içinde mesaj+imza taşınır (demo).";
    hintDec = "DSA: doğrulama için public key gerekir (demo).";
  } else if (a === "DH") {
    hintEnc = "DH: ortak sır + XOR stream demo. Key alanı: demo parametresi/seed olabilir.";
    hintDec = hintEnc;
  } else if (a === "ECC") {
    hintEnc = "ECC: ortak sır + XOR stream demo. Key alanı: demo parametresi/seed olabilir.";
    hintDec = hintEnc;
  } else if (a === "ELGAMAL") {
    hintEnc = "ElGamal: ciphertext JSON/base64 olabilir (wire format bunu taşır).";
    hintDec = "ElGamal: doğru key/parametrelerle çözülür; yanlış key hata verir.";
  } else if (a === "RABIN") {
    hintEnc = "Rabin: ciphertext base64/JSON olabilir (wire format bunu taşır).";
    hintDec = hintEnc;
  } else if (a === "KNAPSACK") {
    hintEnc = "Knapsack: ciphertext base64/JSON olabilir (wire format bunu taşır).";
    hintDec = hintEnc;
  }

  if (keyHint) keyHint.textContent = hintEnc;
  if (decKeyHint) decKeyHint.textContent = hintDec;

  // Hill UI toggle
  if (hillOptions) hillOptions.style.display = (a === "HILL") ? "" : "none";
  if (decHillOptions) decHillOptions.style.display = (a === "HILL") ? "" : "none";
}

// ------------------------------
// Join / Send / Decrypt
// ------------------------------
function getCommonPayload() {
  const username = safeText(usernameInput?.value).trim();
  const room     = safeText(roomInput?.value).trim();
  const algo     = safeText(algoSelect?.value).trim();
  const key      = safeText(keyInput?.value ?? "").trim();

  const payload = { username, room, algo, key };

  // Encrypt: Hill ise hillSize ekle
  if (algo && algo.toUpperCase() === "HILL") {
    const hs = safeText(hillSizeInput?.value || "").trim();
    if (hs) payload.hillSize = hs;
  }

  return payload;
}

// Encrypt algo change
if (algoSelect) {
  algoSelect.addEventListener("change", () => setKeyHints(algoSelect.value));
  setKeyHints(algoSelect.value);
}

// Decrypt algo change
if (decAlgoSelect) {
  decAlgoSelect.addEventListener("change", () => setKeyHints(decAlgoSelect.value));
  setKeyHints(decAlgoSelect.value);
}

let _joinLock = false;

if (joinBtn) {
  joinBtn.addEventListener("click", () => {
    const { username, room } = getCommonPayload();
    if (!username || !room) {
      alert("Username ve Room zorunlu.");
      return;
    }

    // oda değişiyorsa chip'i sıfırla (görsel tutarlılık)
    if (room !== currentRoom) {
      resetRoomUsersChip();
    }

    // spam/double click önle
    if (_joinLock) return;
    _joinLock = true;
    joinBtn.disabled = true;
    setTimeout(() => {
      _joinLock = false;
      joinBtn.disabled = false;
    }, 800);

    currentRoom = room;
    socket.emit("join", { username, room });
  });
}

if (sendBtn) {
  sendBtn.addEventListener("click", () => {
    const msg = safeText(messageInput?.value).trim();
    if (!msg) return;

    const { username, room, algo, key, hillSize } = getCommonPayload();

    const payload = { message: msg, username, room, algo, key };
    if (hillSize) payload.hillSize = hillSize;

    socket.emit("chat_message", payload);

    if (messageInput) messageInput.value = "";
  });
}

// Decrypt butonu
if (decryptBtn) {
  decryptBtn.addEventListener("click", () => {
    const raw = safeText(cipherInput?.value).trim();
    if (!raw) {
      alert("Ciphertext gir.");
      return;
    }

    const { username, room } = getCommonPayload();
    const algo = safeText(decAlgoSelect?.value || algoSelect?.value).trim();
    const decKey = safeText(decKeyInput?.value ?? "").trim();

    // Kullanıcı ciphertext alanına JSON (wire obj) yapıştırmış olabilir
    let wire = null;
    try {
      const maybeObj = JSON.parse(raw);
      if (isWireObj(maybeObj)) wire = maybeObj;
    } catch (_) {}

    if (!wire) {
      wire = normalizeCiphertextToWire(raw);
    }

    // Hill decrypt size
    let hillSize = null;
    if (algo && algo.toUpperCase() === "HILL") {
      hillSize = safeText(decHillSizeInput?.value || hillSizeInput?.value || "").trim();
    }

    const payload = {
      username,
      room,
      algo,
      key: decKey,
      ciphertext: wire
    };
    if (hillSize) payload.hillSize = hillSize;

    socket.emit("decrypt_message", payload);
  });
}

// ------------------------------
// Socket event handlers
// ------------------------------
socket.on("connect", () => console.log(">>> socket connected"));

socket.on("join", (data) => {
  console.log(">>> join ack:", data);
});

// Backend: emit("system_message", {"message": "...", "room": room}, room=room)
socket.on("system_message", (data) => {
  console.log(">>> system_message recv:", data);
  const text = safeText(data?.message || "");
  if (!text) return;
  appendSystemMessage(text);
});

// Backend: emit("room_users", {"room": room, "users": [...]}, room=room)
socket.on("room_users", (data) => {
  console.log(">>> room_users recv:", data);
  if (!data || !Array.isArray(data.users)) return;

  // sadece şu anki oda için göster
  if (currentRoom && data.room && data.room !== currentRoom) return;

  setRoomUsers(data.users);
});

socket.on("chat_message", (data) => {
  console.log(">>> chat_message recv:", data);

  const username = data?.username;
  const algo = data?.algo;
  const wire = data?.ciphertext;

  appendMessage({
    username,
    algo,
    wire,
    created_at: data?.created_at,
    isHistory: false
  });
});

socket.on("history", (items) => {
  console.log(">>> history:", items);
  if (!Array.isArray(items)) return;

  if (messagesList) messagesList.innerHTML = "";

  // history boş gelse bile kullanıcıya bir ipucu ver
  if (items.length === 0) {
    appendSystemMessage("Bu odada henüz mesaj yok. İlk mesajı sen gönder 🙂");
    return;
  }

  items.forEach((it) => {
    appendMessage({
      username: it?.username,
      algo: it?.algo,
      wire: it?.ciphertext,
      created_at: it?.created_at || it?.timestamp || "",
      isHistory: true
    });
  });
});

socket.on("decrypt_result", (data) => {
  console.log(">>> decrypt_result:", data);
  if (!decryptResult) return;

  if (data?.ok) {
    decryptResult.classList.remove("error");
    decryptResult.textContent = data?.plaintext ?? "";
  } else {
    decryptResult.classList.add("error");
    decryptResult.textContent = `HATA: ${data?.error ?? "Çözümleme başarısız"}`;
  }
});
