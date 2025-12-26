from flask_socketio import SocketIO, emit, join_room
from flask import Flask, render_template, request, redirect, url_for, session
from crypto.factory import get_cipher
from db import SessionLocal, Message

import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key'

socketio = SocketIO(app, cors_allowed_origins="*")

USERS = {
    "admin": {"password": "1234", "role": "admin"},
    "bekir": {"password": "12345", "role": "user"}
}

session_aes_keys = {}

# -----------------------------
# Active room user tracking
# -----------------------------
room_users = {}   # { room: set(usernames) }
sid_map = {}      # { sid: {"room": room, "username": username} }


def _emit_room_users(room: str):
    users = sorted(list(room_users.get(room, set())))
    emit("room_users", {"room": room, "users": users}, room=room)


# ----------------------------------------------------
# Wire / DB normalize helpers
# ----------------------------------------------------
def _wire_from_ciphertext(ct):
    """
    ct bytes ise -> {"encoding":"b64","data":"..."}
    ct str ise   -> {"encoding":"str","data":"..."}
    ayrıca DB formatı: "b64:..." / "str:..." desteklenir
    """
    if ct is None:
        return {"encoding": "str", "data": ""}

    if isinstance(ct, (bytes, bytearray)):
        b64 = base64.b64encode(bytes(ct)).decode("utf-8")
        return {"encoding": "b64", "data": b64}

    s = str(ct)

    if s.startswith("b64:"):
        return {"encoding": "b64", "data": s[4:]}
    if s.startswith("str:"):
        return {"encoding": "str", "data": s[4:]}

    return {"encoding": "str", "data": s}


def _db_string_from_ciphertext(ct):
    """
    DB'ye her zaman string kaydet:
      bytes -> "b64:<...>"
      str   -> "str:<...>"
    """
    w = _wire_from_ciphertext(ct)
    if w["encoding"] == "b64":
        return "b64:" + w["data"]
    return "str:" + w["data"]


def _ciphertext_from_wire(wire):
    """
    decrypt için wire objeyi geri çevir:
      {"encoding":"b64","data":"..."} -> bytes
      {"encoding":"str","data":"..."} -> str
    ayrıca kullanıcı "b64:.." "str:.." yapıştırdıysa parse eder
    """
    if wire is None:
        return ""

    if isinstance(wire, dict):
        enc = wire.get("encoding")
        data = wire.get("data", "")
        if enc == "b64":
            try:
                return base64.b64decode(data.encode("utf-8"))
            except Exception:
                return data
        return data

    s = str(wire)
    if s.startswith("b64:"):
        try:
            return base64.b64decode(s[4:].encode("utf-8"))
        except Exception:
            return s[4:]
    if s.startswith("str:"):
        return s[4:]
    return s


@app.route("/")
def index():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("index.html", username=session["username"], role=session.get("role", "user"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        user = USERS.get(username)
        if user and user["password"] == password:
            session["username"] = username
            session["role"] = user["role"]
            return redirect(url_for("index"))
        else:
            error = "Hatalı kullanıcı adı veya şifre."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.pop("username", None)
    session.pop("role", None)
    return redirect(url_for("login"))


@app.route("/admin")
def admin_dashboard():
    if session.get("role") != "admin":
        return redirect(url_for("index"))
    db = SessionLocal()
    messages = db.query(Message).order_by(Message.timestamp.desc()).limit(50).all()
    db.close()
    return render_template("admin.html", username=session["username"], role=session["role"], messages=messages)


@app.post("/admin/delete/<int:msg_id>")
def admin_delete_message(msg_id):
    if session.get("role") != "admin":
        return redirect(url_for("index"))
    db = SessionLocal()
    msg = db.query(Message).filter(Message.id == msg_id).first()
    if msg:
        db.delete(msg)
        db.commit()
    db.close()
    return redirect(url_for("admin_dashboard"))


@app.route("/api/public-key")
def get_public_key():
    rsa = get_cipher("RSA")
    pem = rsa.get_public_key_pem()
    return {"public_key": pem}


@app.route("/api/set-session-key", methods=["POST"])
def set_session_key():
    if "username" not in session:
        return {"success": False, "error": "Giriş yapılmamış."}, 401
    data = request.get_json() or {}
    enc_key = data.get("encrypted_key")
    if not enc_key:
        return {"success": False, "error": "encrypted_key alanı boş."}, 400
    username = session["username"]
    try:
        rsa = get_cipher("RSA")
        aes_key = rsa.decrypt(enc_key)
        session_aes_keys[username] = aes_key
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}, 400


@socketio.on("connect")
def handle_connect():
    pass


@socketio.on("disconnect")
def handle_disconnect():
    # Kim, hangi odadaydı?
    sid = request.sid
    info = sid_map.pop(sid, None)
    if not info:
        return

    room = info.get("room")
    username = info.get("username")

    if room:
        if room in room_users:
            room_users[room].discard(username)
            if len(room_users[room]) == 0:
                room_users.pop(room, None)

        # odadakilere bilgi + güncel kullanıcı listesi
        emit("system_message", {"message": f"{username} odadan ayrıldı.", "room": room}, room=room)
        _emit_room_users(room)


@socketio.on("join")
def handle_join(data):
    username = (data.get("username") or "").strip()
    room = (data.get("room") or "").strip()

    if not username or not room:
        emit("system_message", {"message": "Username/Room boş olamaz.", "room": room or ""}, to=request.sid)
        return

    join_room(room)

    # aktif kullanıcı set'i
    room_users.setdefault(room, set()).add(username)
    sid_map[request.sid] = {"room": room, "username": username}

    # odadakilere sistem mesajı
    emit("system_message", {"message": f"{username} odaya katıldı.", "room": room}, room=room)

    # history sadece bu client'a
    db = SessionLocal()
    history = (
        db.query(Message)
        .filter(Message.room == room)
        .order_by(Message.timestamp.desc())
        .limit(20)
        .all()
    )
    db.close()

    history_data = [
        {
            "username": m.username,
            "ciphertext": _wire_from_ciphertext(m.ciphertext),
            "algo": m.algorithm,
            "created_at": m.timestamp.isoformat() if m.timestamp else ""
        }
        for m in reversed(history)
    ]
    emit("history", history_data, to=request.sid)

    # kullanıcı listesi herkese
    _emit_room_users(room)


@socketio.on("chat_message")
def handle_chat_message(data):
    msg = data.get("message", "")
    username = data.get("username", "")
    room = data.get("room", "")
    algo = data.get("algo", "AES")
    key = data.get("key", "")

    if algo == "AES" and (not key or key.strip() == ""):
        key = session_aes_keys.get(username)

    try:
        cipher = get_cipher(algo)
        if algo == "HILL":
            size = int(data.get("hillSize", 2))
            ciphertext = cipher.encrypt(msg, key, size)
        else:
            ciphertext = cipher.encrypt(msg, key)
    except Exception as e:
        emit("system_message", {"message": f"Şifreleme hatası: {str(e)}", "room": room}, room=room)
        return

    wire = _wire_from_ciphertext(ciphertext)
    db_ciphertext = _db_string_from_ciphertext(ciphertext)

    try:
        db = SessionLocal()
        msg_record = Message(
            username=username,
            room=room,
            algorithm=algo,
            plaintext=msg,
            ciphertext=db_ciphertext
        )
        db.add(msg_record)
        db.commit()
        db.close()
    except Exception:
        pass

    emit(
        "chat_message",
        {
            "username": username,
            "room": room,
            "ciphertext": wire,
            "algo": algo
        },
        room=room
    )


@socketio.on("decrypt_message")
def handle_decrypt_message(data):
    cipher_payload = data.get("ciphertext")
    algo = data.get("algo")
    key = data.get("key", "")

    if not cipher_payload:
        emit("decrypt_result", {"ok": False, "error": "Cipher boş."})
        return

    if algo == "AES" and (not key or key.strip() == "") and "username" in session:
        key = session_aes_keys.get(session["username"], "")

    cipher_text = _ciphertext_from_wire(cipher_payload)

    try:
        cipher = get_cipher(algo)
        if algo == "HILL":
            size = int(data.get("hillSize", 2))
            plaintext = cipher.decrypt(cipher_text, key, size)
        else:
            plaintext = cipher.decrypt(cipher_text, key)
    except Exception as e:
        emit("decrypt_result", {"ok": False, "error": f"{e}"})
        return

    emit("decrypt_result", {"ok": True, "plaintext": plaintext})


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None

    if request.method == "POST":
        username = (request.form.get("username", "")).strip()
        password = (request.form.get("password", "")).strip()
        password2 = (request.form.get("password2", "")).strip()

        # basit validasyon
        if not username or not password:
            error = "Kullanıcı adı ve şifre zorunlu."
        elif len(username) < 3:
            error = "Kullanıcı adı en az 3 karakter olmalı."
        elif len(password) < 4:
            error = "Şifre en az 4 karakter olmalı."
        elif password != password2:
            error = "Şifreler uyuşmuyor."
        elif username in USERS:
            error = "Bu kullanıcı adı zaten alınmış."
        else:
            # USERS dict'e ekle (kalıcı değildir: restartta gider)
            USERS[username] = {"password": password, "role": "user"}
            return redirect(url_for("login"))

    return render_template("register.html", error=error)


if __name__ == "__main__":
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
