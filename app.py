from flask_socketio import SocketIO, emit, join_room
from flask import Flask, render_template, request, redirect, url_for, session
from crypto.symmetric import aes_encrypt, aes_decrypt, des_encrypt, des_decrypt
from crypto.asymmetric import rsa_encrypt, rsa_decrypt
from db import SessionLocal, Message

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key'

socketio = SocketIO(app, cors_allowed_origins="*")


USERS = {
    "admin": "1234",
    "bekir": "12345"
}



@app.route("/")
def index():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("index.html", username=session["username"])


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username in USERS and USERS[username] == password:
            session["username"] = username
            return redirect(url_for("index"))
        else:
            return render_template("login.html", error="Hatalı kullanıcı adı veya şifre.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("login"))



@socketio.on("connect")
def handle_connect():
    print(">>> Yeni bir client bağlandı", flush=True)


@socketio.on("disconnect")
def handle_disconnect():
    print(">>> Bir client bağlantıyı kesti", flush=True)


@socketio.on("join")
def handle_join(data):
    print(">>> join event geldi:", data, flush=True)

    username = data.get("username")
    room = data.get("room")

    join_room(room)

    emit("system_message", {
        "message": f"{username} odaya katıldı.",
        "room": room
    }, room=room)

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

    print(">>> chat_message event (yalnız meta):",
          {"username": data.get("username"), "room": data.get("room"), "algo": data.get("algo")},
          flush=True)

    msg = data["message"]
    username = data["username"]
    room = data["room"]
    algo = data.get("algo", "AES")
    key = data.get("key")


    try:
        if algo == "AES":
            ciphertext = aes_encrypt(msg, key)
        elif algo == "DES":
            ciphertext = des_encrypt(msg, key)
        elif algo == "RSA":
            ciphertext = rsa_encrypt(msg)
        else:
            emit(
                "system_message",
                {"message": f"Desteklenmeyen algoritma: {algo}"},
                room=room
            )
            return

    except Exception as e:
        print(">>> Şifreleme hatası:", e, flush=True)
        emit(
            "system_message",
            {"message": f"Şifreleme hatası: {str(e)}"},
            room=room
        )
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
    except Exception as e:
        print(">>> DB kayıt hatası:", e, flush=True)


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
    print(">>> decrypt_message event:", data, flush=True)

    cipher = data.get("ciphertext")
    algo = data.get("algo")
    key = data.get("key", "")

    if not cipher:
        emit("decrypt_result", {"success": False, "error": "Cipher boş."})
        return

    try:
        if algo == "AES":
            plaintext = aes_decrypt(cipher, key)
        elif algo == "DES":
            plaintext = des_decrypt(cipher, key)
        elif algo == "RSA":
            plaintext = rsa_decrypt(cipher)
        else:
            emit("decrypt_result", {"success": False, "error": "Desteklenmeyen algo."})
            return
    except Exception as e:
        emit("decrypt_result", {"success": False, "error": f"Hata: {e}"})
        return

    emit("decrypt_result", {"success": True, "plaintext": plaintext})



if __name__ == "__main__":
    print(">>> Sunucu başlıyor...", flush=True)
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
