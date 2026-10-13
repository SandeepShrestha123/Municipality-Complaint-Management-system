import os
import re
import sqlite3
import uuid
from datetime import datetime
from functools import wraps

import folium
from flask import (Flask, Response, flash, g, redirect, render_template,
                   request, session, url_for)
from folium import Element
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "portal.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
ALLOWED_PHOTOS = {"png", "jpg", "jpeg", "webp"}

# Default map centre (Kathmandu). Change to your municipality's centre.
DEFAULT_CENTER = (27.7172, 85.3240)

REQUEST_TYPES = {
    "new_pole": "Install a new pole",
    "damaged_pole": "Pole is damaged or leaning",
    "wire_problem": "Wires are hanging, loose or sparking",
    "other": "Another pole problem",
}
WATER_REQUEST_TYPES = {
    "new_pipe": "Install a new water pipe line",
    "leak": "Water pipe is leaking",
    "burst_pipe": "Burst or broken pipe",
    "low_pressure": "Low water pressure",
    "no_supply": "No water supply",
    "contaminated": "Dirty or contaminated water",
    "other_water": "Another water problem",
}
URGENCY_LEVELS = {
    "normal": "Normal",
    "urgent": "Urgent",
    "dangerous": "Dangerous right now",
}

app = Flask(__name__)
# Set a real secret in production:  export SECRET_KEY="long-random-string"
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")
app.config["MAX_CONTENT_LENGTH"] = 6 * 1024 * 1024  # 6 MB photo limit


# ----------------------------------------------------------------- database
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            citizenship_no TEXT NOT NULL UNIQUE,
            phone TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            ward INTEGER NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            service TEXT NOT NULL,              -- 'electricity' or 'water'
            request_type TEXT NOT NULL,
            description TEXT NOT NULL,
            urgency TEXT NOT NULL,
            address TEXT NOT NULL,
            landmark TEXT,
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            photo TEXT,
            status TEXT NOT NULL DEFAULT 'Submitted',
            created_at TEXT NOT NULL
        );
        """
    )
    db.commit()
    db.close()


# --------------------------------------------------------------------- auth
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


@app.before_request
def load_user():
    g.user = None
    uid = session.get("user_id")
    if uid is not None:
        g.user = get_db().execute(
            "SELECT * FROM users WHERE id = ?", (uid,)
        ).fetchone()
        if g.user is None:  # account removed
            session.clear()


@app.route("/")
def index():
    return redirect(url_for("dashboard" if g.user else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("dashboard"))

    errors = {}
    form = request.form
    if request.method == "POST":
        full_name = form.get("full_name", "").strip()
        citizenship_no = form.get("citizenship_no", "").strip()
        phone = form.get("phone", "").strip()
        email = form.get("email", "").strip().lower()
        ward = form.get("ward", "").strip()
        password = form.get("password", "")
        confirm = form.get("confirm", "")

        if len(full_name) < 3:
            errors["full_name"] = "Enter your full name."
        if len(citizenship_no) < 4:
            errors["citizenship_no"] = "Enter your citizenship certificate number."
        if not re.fullmatch(r"\+?\d{7,15}", phone.replace(" ", "")):
            errors["phone"] = "Enter a phone number with 7 to 15 digits."
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            errors["email"] = "Enter a valid email address."
        if not (ward.isdigit() and 1 <= int(ward) <= 35):
            errors["ward"] = "Enter your ward number (1 to 35)."
        if len(password) < 8:
            errors["password"] = "Use at least 8 characters."
        if password != confirm:
            errors["confirm"] = "The two passwords do not match."

        if not errors:
            db = get_db()
            try:
                db.execute(
                    "INSERT INTO users (full_name, citizenship_no, phone, email,"
                    " ward, password_hash, created_at) VALUES (?,?,?,?,?,?,?)",
                    (full_name, citizenship_no, phone.replace(" ", ""), email,
                     int(ward), generate_password_hash(password),
                     datetime.now().isoformat(timespec="seconds")),
                )
                db.commit()
            except sqlite3.IntegrityError:
                errors["email"] = (
                    "An account with this email or citizenship number already exists."
                )
            else:
                flash("Account created. Log in to continue.", "success")
                return redirect(url_for("login"))

    return render_template("register.html", errors=errors, form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("dashboard"))

    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("dashboard"))
        error = "Email or password is not correct."

    return render_template("login.html", error=error,
                           email=request.form.get("email", ""))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# ---------------------------------------------------------------- dashboard
@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM complaints WHERE user_id = ? ORDER BY id DESC LIMIT 5",
        (g.user["id"],),
    ).fetchall()
    counts = db.execute(
        "SELECT COUNT(*) AS total,"
        " SUM(CASE WHEN status != 'Resolved' THEN 1 ELSE 0 END) AS open_count"
        " FROM complaints WHERE user_id = ?",
        (g.user["id"],),
    ).fetchone()
    return render_template(
        "dashboard.html",
        complaints=rows,
        total=counts["total"] or 0,
        open_count=counts["open_count"] or 0,
        request_types={**REQUEST_TYPES, **WATER_REQUEST_TYPES},
    )


# -------------------------------------------------------------- electricity
@app.route("/electricity", methods=["GET", "POST"])
@login_required
def electricity():
    errors = {}
    form = request.form

    if request.method == "POST":
        request_type = form.get("request_type", "")
        description = form.get("description", "").strip()
        urgency = form.get("urgency", "normal")
        address = form.get("address", "").strip()
        landmark = form.get("landmark", "").strip()
        lat_raw, lng_raw = form.get("latitude", ""), form.get("longitude", "")

        if request_type not in REQUEST_TYPES:
            errors["request_type"] = "Choose what you need."
        if urgency not in URGENCY_LEVELS:
            urgency = "normal"
        if len(description) < 10:
            errors["description"] = "Describe the problem in at least 10 characters."

        latitude = longitude = None
        try:
            latitude, longitude = float(lat_raw), float(lng_raw)
            if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
                raise ValueError
        except ValueError:
            errors["location"] = "Select the location on the map."
        if not address and "location" not in errors:
            errors["address"] = "Add an address or the name of the area."

        photo_name = None
        photo = request.files.get("photo")
        if photo and photo.filename:
            ext = photo.filename.rsplit(".", 1)[-1].lower()
            if ext not in ALLOWED_PHOTOS:
                errors["photo"] = "Upload a PNG, JPG or WEBP image."
            else:
                photo_name = f"{uuid.uuid4().hex}_{secure_filename(photo.filename)}"

        if not errors:
            if photo_name:
                photo.save(os.path.join(UPLOAD_DIR, photo_name))
            db = get_db()
            db.execute(
                "INSERT INTO complaints (user_id, service, request_type,"
                " description, urgency, address, landmark, latitude, longitude,"
                " photo, status, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (g.user["id"], "electricity", request_type, description, urgency,
                 address, landmark, latitude, longitude, photo_name, "Submitted",
                 datetime.now().isoformat(timespec="seconds")),
            )
            db.commit()
            flash("Your electricity request has been sent to the municipal office.",
                  "success")
            return redirect(url_for("dashboard"))

    return render_template(
        "electricity.html",
        errors=errors,
        form=form,
        request_types=REQUEST_TYPES,
        urgency_levels=URGENCY_LEVELS,
    )


# -------------------------------------------------------------------- water
@app.route("/water", methods=["GET", "POST"])
@login_required
def water():
    errors = {}
    form = request.form

    if request.method == "POST":
        request_type = form.get("request_type", "")
        description = form.get("description", "").strip()
        urgency = form.get("urgency", "normal")
        address = form.get("address", "").strip()
        landmark = form.get("landmark", "").strip()
        lat_raw, lng_raw = form.get("latitude", ""), form.get("longitude", "")

        if request_type not in WATER_REQUEST_TYPES:
            errors["request_type"] = "Choose the water problem or service you need."
        if urgency not in URGENCY_LEVELS:
            urgency = "normal"
        if len(description) < 10:
            errors["description"] = "Describe the problem in at least 10 characters."

        latitude = longitude = None
        try:
            latitude, longitude = float(lat_raw), float(lng_raw)
            if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
                raise ValueError
        except ValueError:
            errors["location"] = "Select the location on the map."

        if not address and "location" not in errors:
            errors["address"] = "Add an address or the name of the area."

        photo_name = None
        photo = request.files.get("photo")
        if photo and photo.filename:
            ext = photo.filename.rsplit(".", 1)[-1].lower()
            if ext not in ALLOWED_PHOTOS:
                errors["photo"] = "Upload a PNG, JPG or WEBP image."
            else:
                photo_name = f"{uuid.uuid4().hex}_{secure_filename(photo.filename)}"

        if not errors:
            if photo_name:
                photo.save(os.path.join(UPLOAD_DIR, photo_name))
            db = get_db()
            db.execute(
                "INSERT INTO complaints (user_id, service, request_type,"
                " description, urgency, address, landmark, latitude, longitude,"
                " photo, status, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (g.user["id"], "water", request_type, description, urgency,
                 address, landmark, latitude, longitude, photo_name, "Submitted",
                 datetime.now().isoformat(timespec="seconds")),
            )
            db.commit()
            flash("Your water service request has been sent to the municipal office.",
                  "success")
            return redirect(url_for("dashboard"))

    return render_template(
        "water.html",
        errors=errors,
        form=form,
        request_types=WATER_REQUEST_TYPES,
        urgency_levels=URGENCY_LEVELS,
    )


# ---------------------------------------------------------------------- map
@app.route("/map")
@login_required
def map_view():
    """
    OpenStreetMap view built with folium. It is shown inside the location
    dialog of the electricity form. Clicking the map drops a pin and sends the
    coordinates to the form (the parent page) with postMessage.
    Optional query string: /map?latitude=27.7&longitude=85.3 (existing pin).
    """
    try:
        latitude = float(request.args["latitude"])
        longitude = float(request.args["longitude"])
        has_pin = True
    except (KeyError, ValueError):
        latitude, longitude = DEFAULT_CENTER
        has_pin = False

    m = folium.Map(location=[latitude, longitude],
                   zoom_start=16 if has_pin else 13,
                   tiles="OpenStreetMap")

    start_pin = f"[{latitude}, {longitude}]" if has_pin else "null"
    js = f"""
    window.addEventListener('load', function () {{
        var map = {m.get_name()};
        var pin = null;
        function drop(lat, lng, notify) {{
            if (pin) {{ pin.setLatLng([lat, lng]); }}
            else {{ pin = L.marker([lat, lng]).addTo(map); }}
            if (notify) {{
                window.parent.postMessage(
                    {{ type: 'location-picked', lat: lat, lng: lng }},
                    window.location.origin);
            }}
        }}
        var start = {start_pin};
        if (start) {{ drop(start[0], start[1], false); }}
        map.on('click', function (e) {{ drop(e.latlng.lat, e.latlng.lng, true); }});
        window.addEventListener('message', function (e) {{
            if (e.origin !== window.location.origin) return;
            if (e.data && e.data.type === 'move-to') {{
                map.setView([e.data.lat, e.data.lng], 17);
                drop(e.data.lat, e.data.lng, true);
            }}
        }});
    }});
    """
    m.get_root().script.add_child(Element(js))
    return Response(m.get_root().render(), mimetype="text/html")


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
