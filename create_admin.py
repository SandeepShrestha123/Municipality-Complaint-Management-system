"""Run once:  python create_admin.py
Creates (or promotes) an electricity admin account."""
import getpass
import sqlite3
from datetime import datetime

from werkzeug.security import generate_password_hash

from admin_electricity import ADMIN_ROLE, DB_PATH, init_admin_schema

init_admin_schema()
email = input("Admin email: ").strip().lower()
con = sqlite3.connect(DB_PATH)
row = con.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()

if row:
    con.execute("UPDATE users SET role = ? WHERE id = ?", (ADMIN_ROLE, row[0]))
    print("Existing account promoted to electricity admin.")
else:
    name = input("Full name: ").strip() or "Electricity Admin"
    password = getpass.getpass("Password (min 8 chars): ")
    if len(password) < 8:
        raise SystemExit("Password too short.")
    con.execute(
        "INSERT INTO users (full_name, citizenship_no, phone, email, ward,"
        " password_hash, created_at, role) VALUES (?,?,?,?,?,?,?,?)",
        (name, "ADMIN-" + email, "0000000", email, 1,
         generate_password_hash(password),
         datetime.now().isoformat(timespec="seconds"), ADMIN_ROLE))
    print("Admin account created.")
con.commit()
con.close()