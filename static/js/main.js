console.log(">>> main.js yüklendi");

// Sunucuya socket bağlantısı oluştur
const socket = io();
console.log(">>> socket objesi oluşturuldu:", socket);

// HTML elementlerini al
const messagesList = document.getElementById("messages");
const messageInput = document.getElementById("messageInput");
const sendBtn = document.getElementById("sendBtn");

const usernameInput = document.getElementById("usernameInput");
const roomInput = document.getElementById("roomInput");
const joinBtn = document.getElementById("joinBtn");

const algoSelect = document.getElementById("algoSelect");
const keyInput = document.getElementById("keyInput");

// Decrypt alanları
const cipherInput = document.getElementById("cipherInput");
const decKeyInput = document.getElementById("decKeyInput");
const decryptBtn = document.getElementById("decryptBtn");
const decryptResult = document.getElementById("decryptResult");

// Uygulama durumu
let currentUsername = null;
let currentRoom = null;

// Socket olayları
socket.on("connect", () => {
    console.log(">>> Socket CONNECT, id:", socket.id);
});

socket.on("connect_error", (err) => {
    console.error(">>> CONNECT ERROR:", err);
});

socket.on("disconnect", () => {
    console.log(">>> Socket DISCONNECT");
});

// Odaya katıl
joinBtn.addEventListener("click", () => {
    const username = usernameInput.value.trim();
    const room = roomInput.value.trim();

    console.log(">>> joinBtn click, username:", username, "room:", room);

    if (username.length === 0 || room.length === 0) {
        alert("Kullanıcı adı ve oda adı boş olamaz.");
        return;
    }

    currentUsername = username;
    currentRoom = room;

    console.log(">>> socket.emit('join') gönderiliyor...");
    socket.emit("join", {
        username: currentUsername,
        room: currentRoom
    });
});

// GEÇMİŞ MESAJLAR (HISTORY) — SADECE CIPHERTEXT
socket.on("history", (messages) => {
    console.log(">>> history alındı:", messages);

    messages.forEach((data) => {
        const li = document.createElement("li");
        const user = data.username;
        const ct = data.ciphertext;
        const algo = data.algo || "AES";

        li.textContent = `[GEÇMİŞ][${algo}] ${user}: ${ct}`;

        messagesList.appendChild(li);
    });
});

// Sistem mesajları
socket.on("system_message", (data) => {
    console.log(">>> system_message alındı:", data);

    const li = document.createElement("li");
    li.textContent = `[SİSTEM] ${data.message}`;
    li.style.fontStyle = "italic";
    messagesList.appendChild(li);
});

// Chat mesajları — SADECE CIPHERTEXT
socket.on("chat_message", (data) => {
    console.log(">>> chat_message alındı:", data);

    const li = document.createElement("li");

    const user = data.username;
    const ct = data.ciphertext;
    const algo = data.algo || "AES";

    li.textContent = `[${algo}] ${user}: ${ct}`;

    messagesList.appendChild(li);
});

// Mesaj Gönder
sendBtn.addEventListener("click", () => {
    const msg = messageInput.value.trim();
    console.log(">>> sendBtn click, msg(gönderiliyor ama UI'de plaintext gösterilmeyecek)");

    if (msg.length === 0) return;

    if (!currentRoom || !currentUsername) {
        alert("Önce odaya katılman gerekiyor.");
        return;
    }

    const algo = algoSelect.value;
    const key = keyInput.value.trim();

    // Algo -> key doğrulama
    if (algo === "AES" && key.length !== 16) {
        alert("AES-128 için anahtar tam olarak 16 karakter olmalı.");
        return;
    }
    if (algo === "DES" && key.length !== 8) {
        alert("DES için anahtar tam olarak 8 karakter olmalı.");
        return;
    }
    // RSA için key istemiyoruz

    console.log(">>> socket.emit('chat_message') gönderiliyor...");
    socket.emit("chat_message", {
        message: msg,              // plaintext sadece backend'e gidiyor
        username: currentUsername,
        room: currentRoom,
        algo: algo,
        key: key
    });

    messageInput.value = "";
});

// Enter ile gönder
messageInput.addEventListener("keyup", (event) => {
    if (event.key === "Enter") sendBtn.click();
});

// Algo seçimi (RSA seçilince key alanlarını kilitle)
algoSelect.addEventListener("change", () => {
    const algo = algoSelect.value;

    if (algo === "RSA") {
        keyInput.value = "";
        keyInput.disabled = true;

        decKeyInput.value = "";
        decKeyInput.disabled = true;
    } else {
        keyInput.disabled = false;
        decKeyInput.disabled = false;
    }
});

// Şifre Çözme
decryptBtn.addEventListener("click", () => {
    const cipher = cipherInput.value.trim();
    const key = decKeyInput.value.trim();
    const algo = algoSelect.value;

    console.log(">>> decryptBtn click, cipher len:", cipher.length);

    if (cipher.length === 0) {
        alert("Ciphertext boş olamaz.");
        return;
    }

    if (algo === "AES" && key.length !== 16) {
        alert("AES-128 için anahtar tam olarak 16 karakter olmalı.");
        return;
    }
    if (algo === "DES" && key.length !== 8) {
        alert("DES için anahtar tam olarak 8 karakter olmalı.");
        return;
    }
    // RSA için key istemiyoruz

    console.log(">>> socket.emit('decrypt_message') gönderiliyor...");
    socket.emit("decrypt_message", {
        ciphertext: cipher,
        algo: algo,
        key: key
    });
});

// Şifre çözme sonucu — BURADA PLAINTEXT GÖRÜNÜR (BİLEREK)
socket.on("decrypt_result", (data) => {
    console.log(">>> decrypt_result alındı:", data);

    if (!data.success) {
        decryptResult.textContent = "HATA: " + data.error;
        return;
    }

    decryptResult.textContent = data.plaintext;
});
