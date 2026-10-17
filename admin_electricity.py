"""Electricity admin plane (electricity requests only - nothing for water)."""
import hmac
import os
import secrets
import sqlite3
import uuid
from datetime import datetime
from functools import wraps

from flask import (Blueprint, abort, flash, g, redirect, render_template,
                   request, send_from_directory, session, url_for)
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "portal.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")

ADMIN_ROLE = "electricity_admin"
SERVICE = "electricity"
ALLOWED_LETTER = {"png", "jpg", "jpeg", "webp", "pdf"}

# Same labels as REQUEST_TYPES in app.py (copied to avoid a circular import)
TYPE_LABELS = {
    "new_pole": "Install a new pole",
    "damaged_pole": "Pole is damaged or leaning",
    "wire_problem": "Wires are hanging, loose or sparking",
    "other": "Another pole problem",
}
URGENCY_LABELS = {"normal": "Normal", "urgent": "Urgent", "dangerous": "Dangerous right now"}

# Follows your e-governance.docx flow: ward check -> letter -> electric office
STATUSES = ["Submitted", "Ward Verified", "Letter Issued",
            "Office Visit Scheduled", "Resolved", "Rejected"]

bp = Blueprint("elec_admin", __name__, url_prefix="/admin/electricity")


# ----------------------------------------------------------------- database
def db():
    if "db" not in g:                      # same key app.py's get_db() uses,
        g.db = sqlite3.connect(DB_PATH)    # so app.py's teardown closes it
        g.db.row_factory = sqlite3.Row
    return g.db


def init_admin_schema():
    """Safe to run many times: adds users.role and the status_history table."""
    con = sqlite3.connect(DB_PATH)
    cols = [r[1] for r in con.execute("PRAGMA table_info(users)")]
    if "role" not in cols:
        con.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'citizen'")
    con.execute(
        """CREATE TABLE IF NOT EXISTS status_history (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               complaint_id INTEGER NOT NULL REFERENCES complaints(id),
               status TEXT NOT NULL,
               note TEXT,
               changed_by INTEGER NOT NULL REFERENCES users(id),
               changed_at TEXT NOT NULL
           )""")
    hcols = [r[1] for r in con.execute("PRAGMA table_info(status_history)")]
    if "letter_file" not in hcols:
        con.execute("ALTER TABLE status_history ADD COLUMN letter_file TEXT")
    con.commit()
    con.close()


# --------------------------------------------------------------- protection
def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("Please log in as an electricity admin.", "error")
            return redirect(url_for("elec_admin.login"))
        if g.user["role"] != ADMIN_ROLE:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


@bp.app_context_processor
def inject_helpers():
    return {"csrf_token": csrf_token}


# ------------------------------------------------------------------- routes
@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user is not None and g.user["role"] == ADMIN_ROLE:
        return redirect(url_for("elec_admin.dashboard"))

    error = None
    email = request.form.get("email", "").strip().lower()
    if request.method == "POST":
        user = db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        # one message for every failure, so nobody can discover which emails are admins
        if (user and user["role"] == ADMIN_ROLE
                and check_password_hash(user["password_hash"], request.form.get("password", ""))):
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("elec_admin.dashboard"))
        error = "Email or password is not correct, or this is not an admin account."
    return render_template("admin_electricity/login.html", error=error, email=email)


@bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("elec_admin.login"))


@bp.route("/")
@admin_required
def dashboard():
    status = request.args.get("status", "")
    urgency = request.args.get("urgency", "")
    ward = request.args.get("ward", "")

    sql = ("SELECT c.*, u.full_name, u.ward, u.phone FROM complaints c "
           "JOIN users u ON u.id = c.user_id WHERE c.service = ?")
    params = [SERVICE]
    if status in STATUSES:
        sql += " AND c.status = ?"; params.append(status)
    if urgency in URGENCY_LABELS:
        sql += " AND c.urgency = ?"; params.append(urgency)
    if ward.isdigit():
        sql += " AND u.ward = ?"; params.append(int(ward))
    sql += (" ORDER BY CASE c.urgency WHEN 'dangerous' THEN 0 WHEN 'urgent' THEN 1 "
            "ELSE 2 END, c.id DESC")
    rows = db().execute(sql, params).fetchall()

    counts = {s: 0 for s in STATUSES}
    for r in db().execute("SELECT status, COUNT(*) n FROM complaints "
                          "WHERE service = ? GROUP BY status", (SERVICE,)):
        counts[r["status"]] = r["n"]

    return render_template("admin_electricity/dashboard.html", rows=rows,
                           counts=counts, statuses=STATUSES,
                           urgency_labels=URGENCY_LABELS, type_labels=TYPE_LABELS,
                           f_status=status, f_urgency=urgency, f_ward=ward)


def _get_electricity_complaint(complaint_id):
    row = db().execute(
        "SELECT c.*, u.full_name, u.phone, u.email, u.ward, u.citizenship_no "
        "FROM complaints c JOIN users u ON u.id = c.user_id "
        "WHERE c.id = ? AND c.service = ?", (complaint_id, SERVICE)).fetchone()
    if row is None:
        abort(404)          # water complaints are 404 here on purpose
    return row


@bp.route("/<int:complaint_id>")
@admin_required
def detail(complaint_id):
    c = _get_electricity_complaint(complaint_id)
    history = db().execute(
        "SELECT h.*, a.full_name AS admin_name FROM status_history h "
        "JOIN users a ON a.id = h.changed_by WHERE h.complaint_id = ? "
        "ORDER BY h.id DESC", (complaint_id,)).fetchall()
    lat, lng = c["latitude"], c["longitude"]
    map_src = ("https://www.openstreetmap.org/export/embed.html?bbox="
               f"{lng-0.005}%2C{lat-0.003}%2C{lng+0.005}%2C{lat+0.003}"
               f"&layer=mapnik&marker={lat}%2C{lng}")
    return render_template("admin_electricity/detail.html", c=c, history=history,
                           statuses=STATUSES, type_labels=TYPE_LABELS,
                           urgency_labels=URGENCY_LABELS, map_src=map_src)


@bp.route("/<int:complaint_id>/status", methods=["POST"])
@admin_required
def update_status(complaint_id):
    c = _get_electricity_complaint(complaint_id)
    if not hmac.compare_digest(request.form.get("csrf", ""), session.get("csrf", "x")):
        abort(400)
    new_status = request.form.get("status", "")
    note = request.form.get("note", "").strip()

    letter = request.files.get("letter")
    letter_name = None
    if letter and letter.filename:
        ext = letter.filename.rsplit(".", 1)[-1].lower()
        if ext not in ALLOWED_LETTER:
            flash("Letter must be a PNG, JPG, WEBP or PDF file.", "error")
            return redirect(url_for("elec_admin.detail", complaint_id=complaint_id))
        letter_name = f"letter_{uuid.uuid4().hex}_{secure_filename(letter.filename)}"

    if new_status not in STATUSES:
        flash("Choose a valid status.", "error")
    elif new_status == "Rejected" and len(note) < 5:
        flash("Write a reason when rejecting a request.", "error")
    elif new_status == "Letter Issued" and not letter_name:
        flash("Attach the letter when the status is Letter Issued.", "error")
    elif new_status == c["status"] and not note and not letter_name:
        flash("Nothing changed.", "error")
    else:
        if letter_name:
            letter.save(os.path.join(UPLOAD_DIR, letter_name))
        con = db()
        con.execute("UPDATE complaints SET status = ? WHERE id = ?",
                    (new_status, complaint_id))
        con.execute("INSERT INTO status_history (complaint_id, status, note,"
                    " changed_by, changed_at, letter_file) VALUES (?,?,?,?,?,?)",
                    (complaint_id, new_status, note, g.user["id"],
                     datetime.now().isoformat(timespec="seconds"), letter_name))
        con.commit()
        flash(f"Status updated to {new_status}.", "success")
    return redirect(url_for("elec_admin.detail", complaint_id=complaint_id))


@bp.route("/letter/<path:filename>")
@admin_required
def letter(filename):
    ok = db().execute("SELECT 1 FROM status_history WHERE letter_file = ?",
                      (filename,)).fetchone()
    if not ok:
        abort(404)
    return send_from_directory(UPLOAD_DIR, filename)


@bp.route("/photo/<path:filename>")
@admin_required
def photo(filename):
    ok = db().execute("SELECT 1 FROM complaints WHERE photo = ? AND service = ?",
                      (filename, SERVICE)).fetchone()
    if not ok:
        abort(404)
    return send_from_directory(UPLOAD_DIR, filename)