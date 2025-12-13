from flask_socketio import SocketIO, emit, join_room
from flask import Flask, render_template, request, redirect, url_for, session
from crypto.factory import get_cipher
from db import SessionLocal, Message

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key'

socketio = SocketIO(app, cors_allowed_origins="*")

USERS = {
    "admin": {"password": "1234", "role": "admin"},
    "bekir": {"password": "12345", "role": "user"}
}

session_aes_keys = {}


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
    pass


@socketio.on("join")
def handle_join(data):
    username = data.get("username")
    room = data.get("room")
    join_room(room)
    emit("system_message", {"message": f"{username} odaya katıldı.", "room": room}, room=room)

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
            "ciphertext": m.ciphertext,
            "algo": m.algorithm,
            "timestamp": m.timestamp.isoformat() if m.timestamp else ""
        }
        for m in reversed(history)
    ]

    emit("history", history_data, to=request.sid)


@socketio.on("chat_message")
def handle_chat_message(data):
    msg = data["message"]
    username = data["username"]
    room = data["room"]
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
        emit("system_message", {"message": f"Şifreleme hatası: {str(e)}"}, room=room)
        return

    try:
        db = SessionLocal()
        msg_record = Message(
            username=username,
            room=room,
            algorithm=algo,
            plaintext=msg,
            ciphertext=ciphertext
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
            "ciphertext": ciphertext,
            "algo": algo
        },
        room=room
    )


@socketio.on("decrypt_message")
def handle_decrypt_message(data):
    cipher_text = data.get("ciphertext")
    algo = data.get("algo")
    key = data.get("key", "")

    if not cipher_text:
        emit("decrypt_result", {"success": False, "error": "Cipher boş."})
        return

    if algo == "AES" and (not key or key.strip() == "") and "username" in session:
        key = session_aes_keys.get(session["username"], "")

    try:
        cipher = get_cipher(algo)
        if algo == "HILL":
            size = int(data.get("hillSize", 2))
            plaintext = cipher.decrypt(cipher_text, key, size)
        else:
            plaintext = cipher.decrypt(cipher_text, key)
    except Exception as e:
        emit("decrypt_result", {"success": False, "error": f"Hata: {e}"})
        return

    emit("decrypt_result", {"success": True, "plaintext": plaintext})


if __name__ == "__main__":
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
