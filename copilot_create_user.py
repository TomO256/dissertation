# create_user.py
import os, json, hashlib, binascii

USERNAME = "alice"
PASSWORD = "password123"
DB_FILE = "users.json"

salt = os.urandom(8)
pwd_hash = hashlib.pbkdf2_hmac(
    "sha256", PASSWORD.encode(), salt, 100_000
)

entry = {
    USERNAME: {
        "salt": binascii.hexlify(salt).decode(),
        "hash": binascii.hexlify(pwd_hash).decode()
    }
}

try:
    with open(DB_FILE) as f:
        db = json.load(f)
except:
    db = {}

db.update(entry)

with open(DB_FILE, "w") as f:
    json.dump(db, f, indent=2)

print("User created.")