console.log(">>> main.js yüklendi");

const socket = io();
console.log(">>> socket objesi oluşturuldu:", socket);

const messagesList   = document.getElementById("messages");
const messageInput   = document.getElementById("messageInput");
const sendBtn        = document.getElementById("sendBtn");

const usernameInput  = document.getElementById("usernameInput");
const roomInput      = document.getElementById("roomInput");
const joinBtn        = document.getElementById("joinBtn");

const algoSelect     = document.getElementById("algoSelect");
const keyInput       = document.getElementById("keyInput");
const keyHint        = document.getElementById("keyHint");

const hillOptions    = document.getElementById("hillOptions");
const hillSize       = document.getElementById("hillSize");

const cipherInput    = document.getElementById("cipherInput");
const decKeyInput    = document.getElementById("decKeyInput");
const decAlgoSelect  = document.getElementById("decAlgoSelect");
const decKeyHint     = document.getElementById("decKeyHint");
const decryptBtn     = document.getElementById("decryptBtn");
const decryptResult  = document.getElementById("decryptResult");

let currentUsername = null;
let currentRoom = null;

function keyHintText(algo) {
    switch (algo) {
        case "AES":
            return "AES-128 için tam 16 karakterlik anahtar gir (örn: 16 byte).";
        case "DES":
            return "DES için tam 8 karakterlik anahtar gerekir.";
        case "3DES":
            return "3DES için 16 veya 24 karakterlik anahtar kullan.";
        case "BLOWFISH":
            return "Blowfish için 4–56 karakter arasında anahtar girebilirsin.";
        case "RC2":
            return "RC2 için 5–16 karakter uzunluğunda anahtar gir.";
        case "RC5":
            return "RC5 için esnek bir anahtar, en az birkaç karakter girmen yeterli.";
        case "RSA":
            return "RSA için istemciden anahtar girilmez, bu alanı boş bırak.";
        case "MANUAL_AES":
            return "Manual AES için ders senaryona uygun serbest bir anahtar kullan.";
        case "CAESAR":
            return "Caesar için bir tam sayı gir (örn: 3).";
        case "AFFINE":
            return "Affine için 'a,b' formatında gir (örn: 5,8) ve a ile 26 aralarında asal olmalı.";
        case "VIGENERE":
            return "Vigenere için sadece harflerden oluşan bir kelime gir (örn: KRIPTO).";
        case "HILL":
            return "Hill için seçtiğin NxN matris boyutuna göre N² adet sayıyı virgülle gir (örn: 3,10,20,5).";
        default:
            return "";
    }
}

function updateKeyHints() {
    if (algoSelect && keyHint) {
        const algo = algoSelect.value;
        keyHint.textContent = keyHintText(algo);
    }
    if (decAlgoSelect && decKeyHint) {
        const algo = decAlgoSelect.value;
        decKeyHint.textContent = keyHintText(algo);
    }
}

if (algoSelect) {
    algoSelect.addEventListener("change", () => {
        if (algoSelect.value === "HILL") {
            hillOptions.style.display = "block";
        } else {
            hillOptions.style.display = "none";
        }
        updateKeyHints();
    });
}

if (decAlgoSelect) {
    decAlgoSelect.addEventListener("change", () => {
        if (decAlgoSelect.value === "HILL") {
            hillOptions.style.display = "block";
        } else if (algoSelect && algoSelect.value !== "HILL") {
            hillOptions.style.display = "none";
        }
        updateKeyHints();
    });
}

updateKeyHints();

function appendSystemMessage(text) {
    if (!messagesList) return;
    const li = document.createElement("li");
    li.classList.add("system-message");
    li.textContent = text;
    messagesList.appendChild(li);
    messagesList.scrollTop = messagesList.scrollHeight;
}

function appendCipherMessage({ username, room, ciphertext, algo, timestamp }) {
    if (!messagesList) return;

    const li = document.createElement("li");
    li.classList.add("message-item");

    const timePart = timestamp ? ` [${timestamp}]` : "";
    li.innerHTML = `
        <div class="message-meta">
            <span class="message-user">@${username}</span>
            <span class="message-algo">[${algo}]</span>
            <span class="message-room">(${room})</span>
            <span class="message-time">${timePart}</span>
        </div>
        <div class="message-body">
            <span class="cipher-text">${ciphertext}</span>
        </div>
    `;

    const cipherSpan = li.querySelector(".cipher-text");
    if (cipherSpan) {
        cipherSpan.style.cursor = "pointer";
        cipherSpan.addEventListener("click", () => {
            cipherInput.value = ciphertext;
            decAlgoSelect.value = algo;
            decKeyInput.value = "";
            decryptResult.textContent = "";
            updateKeyHints();
            if (algo === "HILL") hillOptions.style.display = "block";
        });
    }

    messagesList.appendChild(li);
    messagesList.scrollTop = messagesList.scrollHeight;
}

if (joinBtn) {
    joinBtn.addEventListener("click", () => {
        const username = usernameInput?.value.trim();
        const room     = roomInput?.value.trim();

        if (!username || !room) {
            alert("Kullanıcı adı ve oda boş olamaz.");
            return;
        }

        currentUsername = username;
        currentRoom     = room;

        socket.emit("join", { username, room });
        appendSystemMessage(`Odaya katıldın: ${room}`);
    });
}

function sendMessage() {
    if (!currentUsername || !currentRoom) {
        alert("Önce odaya katılmalısın.");
        return;
    }

    const message = messageInput.value.trim();
    if (!message) return;

    const algo = algoSelect.value;
    const key  = keyInput.value.trim();

    const payload = {
        username: currentUsername,
        room: currentRoom,
        message,
        algo,
        key
    };

    if (algo === "HILL") {
        payload.hillSize = hillSize.value;
    }

    socket.emit("chat_message", payload);
    messageInput.value = "";
}

if (sendBtn) {
    sendBtn.addEventListener("click", sendMessage);
}

if (messageInput) {
    messageInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter" && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });
}

if (decryptBtn) {
    decryptBtn.addEventListener("click", () => {
        const ciphertext = cipherInput.value.trim();
        const algo = decAlgoSelect.value;
        const key  = decKeyInput.value.trim();

        if (!ciphertext) {
            alert("Çözülecek cipher boş olmamalı.");
            return;
        }

        const payload = { ciphertext, algo, key };

        if (algo === "HILL") {
            payload.hillSize = hillSize.value;
        }

        socket.emit("decrypt_message", payload);
    });
}

socket.on("connect", () => console.log(">>> SocketIO bağlandı:", socket.id));
socket.on("disconnect", () => console.log(">>> SocketIO bağlantısı koptu."));

socket.on("system_message", (data) => {
    if (data?.message) appendSystemMessage(data.message);
});

socket.on("history", (history) => {
    if (!Array.isArray(history)) return;

    history.forEach(m => {
        appendCipherMessage({
            username:  m.username,
            room:      currentRoom,
            ciphertext:m.ciphertext,
            algo:      m.algo || m.algorithm,
            timestamp: m.timestamp
        });
    });
});

socket.on("chat_message", (data) => {
    appendCipherMessage({
        username: data.username,
        room: data.room,
        ciphertext: data.ciphertext,
        algo: data.algo,
        timestamp: ""
    });
});

socket.on("decrypt_result", (data) => {
    if (!decryptResult) return;

    if (!data.success) {
        decryptResult.textContent = "Hata: " + data.error;
        decryptResult.classList.add("error");
        return;
    }

    decryptResult.textContent = data.plaintext;
    decryptResult.classList.remove("error");
});
